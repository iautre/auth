package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgtype"
)

// RFC 8628 设备授权（device flow）。给没有浏览器、没有回调地址的客户端
// （CLI、SSH、容器、CI、对话里的 agent）一条可完成的授权路径。
//
// 安全模型：
//   - device_code 是 CLI 轮询用的长期秘密，库里只存 sha256，明文不落库、不进 URL；
//   - user_code 是给人核对用的短码，明文存储、页面大号展示，泄露无碍；
//   - 确认靠一条原子 UPDATE（WHERE status='pending'）保证只生效一次；
//   - approved 后 CLI 拿 device_code 走 /oauth2/token 的 device_code grant 直接换 token。
//
// RFC 8628 §5.1 限速：user_code 是短码，安全性建立在验证端限速上。

// 设备授权的时间参数。
const (
	deviceCodeLifetime = 10 * time.Minute // device_code 与 user_code 的共用有效期
	devicePollInterval = 5                // 建议轮询间隔（秒）
	devicePollMinGap   = 3 * time.Second  // 低于此间隔轮询返回 slow_down
	deviceCodeByteLen  = 32               // device_code 随机字节数
	deviceUserCodeLen  = 8                // user_code 字符数，格式 XXXX-XXXX
)

// deviceUserCodeAlphabet 去掉 0/O/1/I/L 等易混淆字符。
const deviceUserCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// AuthenticateDeviceClient 为 device_authorization 端点做 client 认证与 scope 校验。
// 与 authorize 不同：这里没有登录用户，client 凭 client_id（public，无 secret）
// 或 client_secret（confidential）自证身份；scope 必须落在 client 登记的范围内。
func (o *OAuth2Service) AuthenticateDeviceClient(ctx context.Context, clientID, clientSecret, scope string) (*AuthorizedClient, error) {
	client, err := o.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	authorized := &AuthorizedClient{ID: client.ID, Name: client.Name, Secret: client.Secret, Scopes: client.Scopes}

	effectiveScope := scope
	if strings.TrimSpace(effectiveScope) == "" {
		effectiveScope = authorized.DefaultScope()
	}
	if err := validateAuthScopes(client.Scopes, effectiveScope); err != nil {
		return nil, err
	}
	return authorized, nil
}

// ClientName 按 client_id 取展示名，用于确认页把「谁在申请授权」摆清楚。
func (o *OAuth2Service) ClientName(ctx context.Context, clientID string) (string, error) {
	client, err := o.getQueries(ctx).GetOAuth2Client(ctx, clientID)
	if err != nil {
		return "", err
	}
	return client.Name, nil
}

// hashDeviceCode 计算 device_code 的 sha256 摘要。明文 device_code 不进数据库。
func hashDeviceCode(deviceCode string) string {
	sum := sha256.Sum256([]byte(deviceCode))
	return hex.EncodeToString(sum[:])
}

// newUserCode 生成 8 位免混淆短码，格式 XXXX-XXXX。
func newUserCode() string {
	b := make([]byte, deviceUserCodeLen)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(deviceUserCodeAlphabet))))
		if err != nil {
			// 加密随机源故障属致命错误，退回时间戳低位兜底不现实；
			// 直接用 panic 暴露，避免静默生成可预测的码。
			panic("device user code: crypto/rand failed: " + err.Error())
		}
		b[i] = deviceUserCodeAlphabet[n.Int64()]
	}
	raw := string(b)
	return raw[:4] + "-" + raw[4:]
}

// normalizeUserCode 把用户输入规整成库里存的形态：去空格、转大写。
func normalizeUserCode(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

// DeviceAuthorizationResponse 是 /oauth2/device_authorization 的响应。
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// DeviceAuthorization 创建一次设备授权：生成 device_code / user_code 并落库。
// client 认证与 scope 校验在 handler 侧先行完成（复用 authorize 的既有校验），
// 这里只负责生成码、存库、返回给客户端。
func (o *OAuth2Service) DeviceAuthorization(ctx context.Context, clientID, scope, resource string) (*DeviceAuthorizationResponse, error) {
	resource, err := normalizeResource(resource)
	if err != nil {
		return nil, err
	}

	deviceCode := gowk.GenerateRandomString(deviceCodeByteLen)
	userCode := newUserCode()
	expires := time.Now().Add(deviceCodeLifetime)

	if _, err := o.getQueries(ctx).CreateOAuth2DeviceCode(ctx, db2.CreateOAuth2DeviceCodeParams{
		DeviceCodeHash:  hashDeviceCode(deviceCode),
		UserCode:        userCode,
		ClientID:        clientID,
		Scope:           pgtype.Text{String: scope, Valid: scope != ""},
		Resource:        pgtype.Text{String: resource, Valid: resource != ""},
		Expires:         pgtype.Timestamptz{Time: expires, Valid: true},
		IntervalSeconds: devicePollInterval,
	}); err != nil {
		return nil, fmt.Errorf("failed to store device code: %w", err)
	}

	base := strings.TrimRight(gowk.BaseURL(), "/")
	return &DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         base + "/device",
		VerificationURIComplete: base + "/device?user_code=" + userCode,
		ExpiresIn:               int64(deviceCodeLifetime.Seconds()),
		Interval:                devicePollInterval,
	}, nil
}

// PollDeviceToken 是 CLI 侧轮询端点背后的状态机。
//
// 返回：
//   - 已批准：true + nil error，客户端拿 device_code 走 token 端点换 token；
//   - 未批准：false + *OAuthError（authorization_pending / slow_down / access_denied / expired_token）；
//   - 其他：包装后的内部错误。
func (o *OAuth2Service) PollDeviceToken(ctx context.Context, deviceCode string) (bool, error) {
	rec, err := o.getQueries(ctx).GetOAuth2DeviceCodeByHash(ctx, hashDeviceCode(deviceCode))
	if err != nil {
		// 查无此码：不区分「从没申请过」和「已清理」，避免可探测。
		return false, newOAuthError(OAuthErrAccessDenied, "invalid device_code", http.StatusBadRequest)
	}

	switch rec.Status {
	case "approved":
		return true, nil

	case "denied":
		return false, newOAuthError(OAuthErrAccessDenied, "the user denied the request", http.StatusBadRequest)

	case "pending":
		if time.Now().After(rec.Expires.Time) {
			return false, newOAuthError(OAuthErrExpiredToken, "device authorization expired", http.StatusBadRequest)
		}
		// 限速：低于最小间隔的连续轮询回 slow_down，并记录本次轮询时间。
		if rec.LastPolled.Valid && time.Since(rec.LastPolled.Time) < devicePollMinGap {
			return false, newOAuthError(OAuthErrSlowDown, "polling too frequently", http.StatusBadRequest)
		}
		if err := o.getQueries(ctx).RecordOAuth2DeviceCodePoll(ctx, rec.DeviceCodeHash); err != nil {
			return false, fmt.Errorf("failed to record poll: %w", err)
		}
		return false, newOAuthError(OAuthErrAuthorizationPending, "authorization pending", http.StatusBadRequest)

	default:
		// expired 或未知状态：统一当过期。
		return false, newOAuthError(OAuthErrExpiredToken, "device authorization expired", http.StatusBadRequest)
	}
}

// DeviceUserCodeStatus 是确认页用来判断「这条链接还有没有效」的结果。
type DeviceUserCodeStatus int

const (
	DevicePending DeviceUserCodeStatus = iota // 待确认，可渲染确认页
	DeviceInvalid                             // 已用/已拒/过期/不存在，一律失效页
)

// LookupPendingDeviceUserCode 按 user_code 查一条待确认请求。
// 只在 status='pending' 且未过期时命中；其余情况（已用、已拒、过期、码不存在）
// 都返回 Invalid，对外行为一致，不泄露「谁在请求什么」。
func (o *OAuth2Service) LookupPendingDeviceUserCode(ctx context.Context, userCode string) (DeviceUserCodeStatus, *db2.AuthOauth2DeviceCode) {
	rec, err := o.getQueries(ctx).GetPendingOAuth2DeviceCodeByUserCode(ctx, normalizeUserCode(userCode))
	if err != nil {
		return DeviceInvalid, nil
	}
	return DevicePending, &rec
}

// ApproveDeviceAuthorization 处理用户在确认页点「允许」。
// 原子地把 pending 翻成 approved 并记下用户；返回 (是否成功, 错误)。
// 失败（影响 0 行）表示该请求已失效（被别人确认过、已拒绝、已过期）。
func (o *OAuth2Service) ApproveDeviceAuthorization(ctx context.Context, userCode string, userID int64) (bool, error) {
	_, err := o.getQueries(ctx).ApproveOAuth2DeviceCode(ctx, db2.ApproveOAuth2DeviceCodeParams{
		UserCode: normalizeUserCode(userCode),
		UserID:   pgtype.Int8{Int64: userID, Valid: true},
	})
	if err != nil {
		return false, nil // 影响 0 行：已失效
	}
	return true, nil
}

// DenyDeviceAuthorization 处理用户在确认页点「拒绝」。
func (o *OAuth2Service) DenyDeviceAuthorization(ctx context.Context, userCode string) (bool, error) {
	_, err := o.getQueries(ctx).DenyOAuth2DeviceCode(ctx, normalizeUserCode(userCode))
	if err != nil {
		return false, nil // 影响 0 行：已失效
	}
	return true, nil
}
