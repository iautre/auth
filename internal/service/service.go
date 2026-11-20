package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgtype"
)

// BaseService provides common database operations
type BaseService struct{}

// getQueries returns database queries instance
func (s *BaseService) getQueries(ctx context.Context) *db2.Queries {
	return db2.New(gowk.DB(ctx))
}

type UserService struct {
	BaseService
}

func (u *UserService) GetById(ctx context.Context, id int64) (db2.AuthUser, error) {
	if id <= 0 {
		return db2.AuthUser{}, gowk.NewError("invalid user ID")
	}
	return u.getQueries(ctx).UserById(ctx, id)
}

func (u *UserService) GetByPhone(ctx context.Context, phone string) (db2.AuthUser, error) {
	if phone == "" {
		return db2.AuthUser{}, gowk.NewError("phone number cannot be empty")
	}
	if !isValidPhone(phone) {
		return db2.AuthUser{}, gowk.NewError("invalid phone number format")
	}
	return u.getQueries(ctx).UserByPhone(ctx, pgtype.Text{String: phone, Valid: true})
}

// getByAccount 按账号形态查用户：含 @ 视为邮箱，否则视为手机号。
// TOTP 登录与邮箱验证码登录共用同一套账号标识口径，避免两处判断分叉。
func (u *UserService) getByAccount(ctx context.Context, account string) (db2.AuthUser, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return db2.AuthUser{}, gowk.NewError("account cannot be empty")
	}
	if strings.Contains(account, "@") {
		return u.getQueries(ctx).UserByEmail(ctx, normalizeTarget(account))
	}
	return u.GetByPhone(ctx, account)
}

// Login 登录：账号可以是手机号或邮箱，凭据是用户绑定的 TOTP 动态口令。
// 账号不存在与凭据错误一律返回同一句 "user not found"，不区分——避免暴露账号是否注册。
func (u *UserService) Login(ctx context.Context, params *dto.LoginParams) (db2.AuthUser, error) {
	user, err := u.getByAccount(ctx, params.Account)
	if err != nil {
		return db2.AuthUser{}, gowk.NewError("user not found")
	}

	// Check user status
	if !user.Enabled {
		return db2.AuthUser{}, gowk.NewError("account is disabled")
	}

	var otpService OTPService
	verified, err := otpService.VerifyLogin(ctx, user.ID, params.Code)
	if err != nil {
		return db2.AuthUser{}, fmt.Errorf("verify OTP: %w", err)
	}
	if !verified {
		return db2.AuthUser{}, gowk.NewError("invalid verification code")
	}

	// Update login info (best-effort：失败不阻断登录，但需要记录便于排查)
	if err := u.UpdateLoginInfo(ctx, user.ID); err != nil {
		slog.WarnContext(ctx, "update login info failed", "user_id", user.ID, "err", err)
	}

	return user, nil
}

// ResetOTPCode 重新生成用户 OTP 秘钥并写库，返回新秘钥。
func (u *UserService) ResetOTPCode(ctx context.Context, userId int64) (string, error) {
	if userId <= 0 {
		return "", gowk.NewError("invalid user ID")
	}
	var otpService OTPService
	return otpService.ResetCredentials(ctx, userId)
}

// UpdateLoginInfo 更新用户最近登录时间并自增登录计数。
func (u *UserService) UpdateLoginInfo(ctx context.Context, userId int64) error {
	if userId <= 0 {
		return gowk.NewError("invalid user ID")
	}
	return u.getQueries(ctx).UpdateUserLoginInfo(ctx, userId)
}

// OAuth2 Service
type OAuth2Service struct {
	BaseService
}

// NewOAuth2Service creates a new OAuth2Service.
// 真正的 *db2.Queries 通过 ctx 在每次调用时按需获取（BaseService.getQueries），
// 这里不缓存以避免 service 与请求 ctx 的生命周期错位。
func NewOAuth2Service(_ context.Context) *OAuth2Service {
	return &OAuth2Service{}
}

// GenerateAuthorizationCode 生成并落库一次性授权码。
// codeChallenge / codeChallengeMethod 用于 PKCE（RFC 7636）：
//   - 不传则代表非 PKCE 流；
//   - method 仅接受 "S256" / "plain"，DTO 已做绑定校验，这里再做一道保险。
func (o *OAuth2Service) GenerateAuthorizationCode(ctx context.Context, clientID string, userID int64, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource string) (string, error) {
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "plain"
		}
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			return "", invalidRequest("unsupported code_challenge_method")
		}
	} else if codeChallengeMethod != "" {
		return "", invalidRequest("code_challenge_method requires code_challenge")
	}

	resource, err := normalizeResource(resource)
	if err != nil {
		return "", err
	}

	code := gowk.GenerateRandomString(32)
	expires := time.Now().Add(10 * time.Minute)

	authCode := db2.CreateOAuth2AuthorizationCodeParams{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectUri:         pgtype.Text{String: redirectURI, Valid: redirectURI != ""},
		Scope:               pgtype.Text{String: scope, Valid: scope != ""},
		State:               pgtype.Text{String: state, Valid: state != ""},
		Nonce:               pgtype.Text{String: nonce, Valid: nonce != ""},
		CodeChallenge:       pgtype.Text{String: codeChallenge, Valid: codeChallenge != ""},
		CodeChallengeMethod: pgtype.Text{String: codeChallengeMethod, Valid: codeChallenge != ""},
		Resource:            pgtype.Text{String: resource, Valid: resource != ""},
		Expires:             pgtype.Timestamptz{Time: expires, Valid: true},
	}

	if _, err := o.getQueries(ctx).CreateOAuth2AuthorizationCode(ctx, authCode); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

// normalizeResource 按 RFC 8707 §2 校验资源指示：必须是绝对 URI、不含 fragment。
// 空值合法，表示客户端没有声明资源，签发的 token 不绑定 audience。
func normalizeResource(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 {
		return "", invalidRequest("resource is too long")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", invalidRequest("resource must be an absolute URI")
	}
	if parsed.Fragment != "" {
		return "", invalidRequest("resource must not contain a fragment")
	}
	return raw, nil
}

// AuthorizedClient 是 authorize 第一阶段校验通过后的客户端快照。
// 拆成两步是为了让调用方能区分"client 本身不可信"（不得重定向）与
// "后续参数有误"（可以带 error 回到 redirect_uri），见 RFC 6749 §4.1.2.1。
type AuthorizedClient struct {
	ID     string
	Name   string
	Secret string
	Scopes string
}

// DefaultScope 返回授权请求未携带 scope 时应当使用的集合：优先用该 client
// 自己登记的 scope，登记为空（视为不限制）才退到全局默认。
// 不能无条件用全局默认——只登记了 openid 的 client 会被判成越权 scope。
func (c *AuthorizedClient) DefaultScope() string {
	var scopes []string
	if err := json.Unmarshal([]byte(c.Scopes), &scopes); err == nil && len(scopes) > 0 {
		return strings.Join(scopes, " ")
	}
	return DefaultAuthorizeScope
}

// ValidateClientRedirect 只判断"能否把用户送回这个客户端"：client 存在、启用、
// redirect_uri 与登记值精确相等。这一步失败时按 RFC 6749 §4.1.2.1 不得重定向，
// 必须就地报错，避免把用户导向未登记地址。
func (o *OAuth2Service) ValidateClientRedirect(ctx context.Context, clientID, redirectURI string) (*AuthorizedClient, error) {
	client, err := o.getQueries(ctx).GetOAuth2Client(ctx, clientID)
	if err != nil {
		return nil, invalidRequest("unknown client_id")
	}
	if !client.Enabled {
		return nil, invalidRequest("client is disabled")
	}

	var redirectURIs []string
	if err := json.Unmarshal([]byte(client.RedirectUris), &redirectURIs); err != nil {
		return nil, invalidRequest("client redirect_uris is malformed")
	}
	for _, uri := range redirectURIs {
		if uri == redirectURI {
			return &AuthorizedClient{ID: client.ID, Name: client.Name, Secret: client.Secret, Scopes: client.Scopes}, nil
		}
	}
	return nil, invalidRequest("redirect_uri does not match any registered value")
}

// validateAuthScopes 校验请求的 scope 全部落在 client 登记的范围内。
// 登记列表为空视为未限制（保持历史 client 可用）；非空则严格限制，
// 防止客户端索取未获授权的用户字段（如未登记 phone 却要求手机号）。
func validateAuthScopes(clientScopesJSON, requested string) error {
	var allowed []string
	if err := json.Unmarshal([]byte(clientScopesJSON), &allowed); err != nil {
		return invalidRequest("client scopes is malformed")
	}
	if len(allowed) == 0 {
		return nil
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}
	for _, s := range strings.Fields(requested) {
		if _, ok := allowedSet[s]; !ok {
			return invalidScope("scope not registered for this client: " + s)
		}
	}
	return nil
}

// ValidateAuthRequest 在 client 已确认可信之后校验 scope 与 PKCE。
func (o *OAuth2Service) ValidateAuthRequest(client *AuthorizedClient, req *dto.OAuth2AuthRequest) error {
	if err := validateAuthScopes(client.Scopes, req.Scope); err != nil {
		return err
	}
	return validatePublicClientPKCE(client.Secret, req.CodeChallenge, req.CodeChallengeMethod)
}

// ValidateOAuth2AuthRequest 一次性完成 authorize 的全部校验。
func (o *OAuth2Service) ValidateOAuth2AuthRequest(ctx context.Context, req *dto.OAuth2AuthRequest) (*AuthorizedClient, error) {
	client, err := o.ValidateClientRedirect(ctx, req.ClientID, req.RedirectURI)
	if err != nil {
		return nil, err
	}
	if err := o.ValidateAuthRequest(client, req); err != nil {
		return nil, err
	}
	return client, nil
}

// ValidateAuthorizationCode 取出并校验授权码。
// redirectURI 用于回放期 redirect_uri 强一致校验（RFC 6749 §4.1.3）：
// 颁发授权码时存入了 redirect_uri，则换 token 时必须一字不差地传回。
func (o *OAuth2Service) ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI string) (*db2.AuthOauth2AuthorizationCode, error) {
	queries := o.getQueries(ctx)

	authCode, err := queries.GetOAuth2AuthorizationCode(ctx, code)
	if err != nil {
		return nil, invalidGrant("authorization code not found")
	}

	if authCode.ClientID != clientID {
		return nil, invalidGrant("client ID mismatch")
	}

	if authCode.Expires.Time.Before(time.Now()) {
		return nil, invalidGrant("authorization code expired")
	}

	// redirect_uri 必须与授权阶段一致；允许未绑定时跳过比对（罕见场景，保守兼容）。
	if authCode.RedirectUri.Valid && authCode.RedirectUri.String != "" {
		if redirectURI == "" || authCode.RedirectUri.String != redirectURI {
			return nil, invalidGrant("redirect_uri mismatch")
		}
	}

	return &authCode, nil
}

// ConsumeAuthorizationCode 原子删除并返回授权码。调用方必须先完成 redirect_uri / PKCE 校验；
// 若并发请求已经消费了同一 code，这里会返回错误，避免同一授权码换出多套 token。
func (o *OAuth2Service) ConsumeAuthorizationCode(ctx context.Context, code, clientID string) (*db2.AuthOauth2AuthorizationCode, error) {
	authCode, err := o.getQueries(ctx).ConsumeOAuth2AuthorizationCode(ctx, db2.ConsumeOAuth2AuthorizationCodeParams{
		Code:     code,
		ClientID: clientID,
	})
	if err != nil {
		return nil, invalidGrant("authorization code already used or expired")
	}
	return &authCode, nil
}

// resolveTokenTTL 读取 client 配置的 TTL。列定义是 NOT NULL DEFAULT，
// 创建与更新两侧都不会写入 0 或负数，因此这里不做兜底：读不到就返回错误。
func (o *OAuth2Service) resolveTokenTTL(ctx context.Context, clientID string) (int64, int64, error) {
	client, err := o.getQueries(ctx).GetOAuth2Client(ctx, clientID)
	if err != nil {
		return 0, 0, fmt.Errorf("读取 client %s 的 token TTL 失败: %w", clientID, err)
	}
	return client.AccessTokenTtl, client.RefreshTokenTtl, nil
}

// generateAccessToken 生成并落库一枚 access token，返回 token 字符串。
// audience 为空表示这次签发没有声明资源（RFC 8707 未启用或客户端没传），
// 校验侧据此按「不绑定」处理，保持对历史 token 与旧客户端的兼容。
func (o *OAuth2Service) generateAccessToken(ctx context.Context, clientID string, userID int64, scope pgtype.Text, audience string, ttl int64) (string, error) {
	accessToken := gowk.GenerateRandomString(64)
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	if _, err := o.getQueries(ctx).CreateOAuth2Token(ctx, db2.CreateOAuth2TokenParams{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ClientID:    clientID,
		UserID:      userID,
		Scope:       scope,
		Audience:    pgtype.Text{String: audience, Valid: audience != ""},
		Expires:     pgtype.Timestamptz{Time: expires, Valid: true},
	}); err != nil {
		return "", fmt.Errorf("failed to store access token: %w", err)
	}
	return accessToken, nil
}

// generateRefreshToken 生成并落库一枚 refresh token，返回 token 字符串。
// audience 必须随刷新继承，否则刷新一次就把资源绑定洗掉了。
func (o *OAuth2Service) generateRefreshToken(ctx context.Context, clientID string, userID int64, scope pgtype.Text, audience string, ttl int64) (string, error) {
	refreshToken := gowk.GenerateRandomString(64)
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	if _, err := o.getQueries(ctx).CreateOAuth2RefreshToken(ctx, db2.CreateOAuth2RefreshTokenParams{
		RefreshToken: refreshToken,
		ClientID:     clientID,
		UserID:       userID,
		Scope:        scope,
		Audience:     pgtype.Text{String: audience, Valid: audience != ""},
		Expires:      pgtype.Timestamptz{Time: expires, Valid: true},
	}); err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}
	return refreshToken, nil
}

// Helper function to build token response
func (o *OAuth2Service) buildTokenResponse(ctx context.Context, accessToken, refreshToken string, scope pgtype.Text, accessTTL int64, includeIDToken bool, userID int64, clientID, nonce string) (*dto.OAuth2TokenResponse, error) {
	response := &dto.OAuth2TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    accessTTL,
		RefreshToken: refreshToken,
		Scope:        scope.String,
	}

	// Generate ID Token if OIDC scope is requested
	if includeIDToken && strings.Contains(scope.String, "openid") {
		idToken, err := DefaultOIDCService().GenerateIDToken(ctx, userID, clientID, nonce, scope.String, accessToken, accessTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ID token: %w", err)
		}
		response.IDToken = idToken
	}

	return response, nil
}

// ExchangeToken handles OAuth2 token exchange for all grant types
func (o *OAuth2Service) ExchangeToken(ctx context.Context, req *dto.OAuth2TokenRequest) (*dto.OAuth2TokenResponse, error) {
	switch req.GrantType {
	case "authorization_code":
		return o.handleAuthorizationCodeGrant(ctx, req)
	case "refresh_token":
		return o.handleRefreshTokenGrant(ctx, req)
	case "client_credentials":
		return o.handleClientCredentialsGrant(ctx, req)
	case "urn:ietf:params:oauth:grant-type:device_code":
		return o.handleDeviceCodeGrant(ctx, req)
	default:
		return nil, newOAuthError(OAuthErrUnsupportedGrantType, "unsupported grant_type: "+req.GrantType, http.StatusBadRequest)
	}
}

// handleAuthorizationCodeGrant handles authorization_code grant type
func (o *OAuth2Service) handleAuthorizationCodeGrant(ctx context.Context, req *dto.OAuth2TokenRequest) (*dto.OAuth2TokenResponse, error) {
	client, err := o.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !o.supportsGrantType(client.GrantTypes, "authorization_code") {
		return nil, newOAuthError(OAuthErrUnauthorizedClient, "client does not support authorization_code grant", http.StatusBadRequest)
	}
	authCode, err := o.ValidateAuthorizationCode(ctx, req.Code, req.ClientID, req.RedirectURI)
	if err != nil {
		return nil, err
	}
	challenge := ""
	if authCode.CodeChallenge.Valid {
		challenge = authCode.CodeChallenge.String
	}
	method := ""
	if authCode.CodeChallengeMethod.Valid {
		method = authCode.CodeChallengeMethod.String
	}
	if err := validatePublicClientPKCE(client.Secret, challenge, method); err != nil {
		return nil, err
	}
	if err := o.verifyPKCE(authCode, req.CodeVerifier); err != nil {
		return nil, err
	}
	authCode, err = o.ConsumeAuthorizationCode(ctx, req.Code, req.ClientID)
	if err != nil {
		return nil, err
	}
	accessTTL, refreshTTL, err := o.resolveTokenTTL(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	// audience 取自授权时声明的 resource。token 端点若也带 resource，只允许与之相同，
	// 否则等于换 token 时临时扩大访问范围（RFC 8707 §2 要求两端一致）。
	audience := ""
	if authCode.Resource.Valid {
		audience = authCode.Resource.String
	}
	if requested := strings.TrimSpace(req.Resource); requested != "" && requested != audience {
		return nil, newOAuthError(OAuthErrInvalidTarget, "resource does not match the authorization request", http.StatusBadRequest)
	}
	accessToken, err := o.generateAccessToken(ctx, authCode.ClientID, authCode.UserID, authCode.Scope, audience, accessTTL)
	if err != nil {
		return nil, err
	}
	refreshToken, err := o.generateRefreshToken(ctx, authCode.ClientID, authCode.UserID, authCode.Scope, audience, refreshTTL)
	if err != nil {
		return nil, err
	}
	return o.buildTokenResponse(ctx, accessToken, refreshToken, authCode.Scope, accessTTL, true, authCode.UserID, authCode.ClientID, authCode.Nonce.String)
}

// validatePublicClientPKCE enforces RFC 7636 for native/browser clients that
// cannot safely hold a client secret. Confidential clients may still opt into
// PKCE, but public clients must use S256 rather than plain or no challenge.
func validatePublicClientPKCE(clientSecret, codeChallenge, codeChallengeMethod string) error {
	if clientSecret == "" && (codeChallenge == "" || codeChallengeMethod != "S256") {
		return invalidRequest("public client requires PKCE S256")
	}
	return nil
}

// handleRefreshTokenGrant handles refresh_token grant type.
// 采用 refresh token rotation：换 access token 时同时签发新 refresh token，并回收旧的，避免数据库孤儿、降低重放风险。
func (o *OAuth2Service) handleRefreshTokenGrant(ctx context.Context, req *dto.OAuth2TokenRequest) (*dto.OAuth2TokenResponse, error) {
	queries := o.getQueries(ctx)
	token, err := queries.GetOAuth2RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, invalidGrant("invalid or expired refresh token")
	}
	if time.Now().After(token.Expires.Time) {
		return nil, invalidGrant("refresh token expired")
	}
	// refresh 流程也必须验证 client。req.ClientID 若提供则需与 token 匹配，避免跨 client 串用。
	if req.ClientID != "" && req.ClientID != token.ClientID {
		return nil, invalidGrant("client_id does not match refresh token")
	}
	client, err := o.authenticateClient(ctx, token.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !o.supportsGrantType(client.GrantTypes, "refresh_token") {
		return nil, newOAuthError(OAuthErrUnauthorizedClient, "client does not support refresh_token grant", http.StatusBadRequest)
	}
	accessTTL, refreshTTL, err := o.resolveTokenTTL(ctx, token.ClientID)
	if err != nil {
		return nil, err
	}
	// 刷新只能继承原 audience：允许在刷新时换 resource 就等于一张 token 可以
	// 通过反复刷新漂移到任何服务，资源绑定形同虚设。
	audience := ""
	if token.Audience.Valid {
		audience = token.Audience.String
	}
	if requested := strings.TrimSpace(req.Resource); requested != "" && requested != audience {
		return nil, newOAuthError(OAuthErrInvalidTarget, "resource does not match the refresh token", http.StatusBadRequest)
	}
	accessToken, err := o.generateAccessToken(ctx, token.ClientID, token.UserID, token.Scope, audience, accessTTL)
	if err != nil {
		return nil, err
	}
	newRefreshToken, err := o.generateRefreshToken(ctx, token.ClientID, token.UserID, token.Scope, audience, refreshTTL)
	if err != nil {
		return nil, err
	}
	// 旧 refresh token 立即作废；失败仅记日志，不阻断本次刷新（已颁发新 token）。
	if err := queries.RevokeOAuth2RefreshToken(ctx, req.RefreshToken); err != nil {
		slog.WarnContext(ctx, "revoke old refresh token failed", "client_id", token.ClientID, "err", err)
	}
	return o.buildTokenResponse(ctx, accessToken, newRefreshToken, token.Scope, accessTTL, false, 0, "", "")
}

// authenticateClient 校验 client 存在、启用，并对 confidential client 做 secret 校验。
// 当 client.Secret 非空时视为 confidential client，必须提供匹配的 client_secret；
// 空 secret 视为 public client，调用方应配合 PKCE 防御。
func (o *OAuth2Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (*db2.AuthOauth2Client, error) {
	if clientID == "" {
		return nil, invalidClient("client_id is required")
	}
	client, err := o.getQueries(ctx).GetOAuth2Client(ctx, clientID)
	if err != nil {
		return nil, invalidClient("unknown client_id")
	}
	if !client.Enabled {
		return nil, invalidClient("client is disabled")
	}
	if client.Secret != "" {
		if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
			return nil, invalidClient("invalid client credentials")
		}
	}
	return &client, nil
}

// verifyPKCE 校验 code_verifier 是否匹配授权阶段提交的 code_challenge。
// 颁发时未带 code_challenge → 非 PKCE 流，code_verifier 必须不出现；
// 颁发时带了 → 必须给出 code_verifier，且按 method 反推后做常时比较。
func (o *OAuth2Service) verifyPKCE(authCode *db2.AuthOauth2AuthorizationCode, codeVerifier string) error {
	hasChallenge := authCode.CodeChallenge.Valid && authCode.CodeChallenge.String != ""
	if !hasChallenge {
		if codeVerifier != "" {
			return invalidGrant("code_verifier provided but authorization code was not bound to PKCE")
		}
		return nil
	}
	if codeVerifier == "" {
		return invalidGrant("code_verifier is required")
	}
	method := "plain"
	if authCode.CodeChallengeMethod.Valid && authCode.CodeChallengeMethod.String != "" {
		method = authCode.CodeChallengeMethod.String
	}
	var expected string
	switch method {
	case "plain":
		expected = codeVerifier
	case "S256":
		sum := sha256.Sum256([]byte(codeVerifier))
		expected = base64.RawURLEncoding.EncodeToString(sum[:])
	default:
		return invalidGrant("unsupported code_challenge_method")
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(authCode.CodeChallenge.String)) != 1 {
		return invalidGrant("invalid code_verifier")
	}
	return nil
}

// handleClientCredentialsGrant handles client_credentials grant type.
// 复用 authenticateClient 做存在/启用/secret 校验，再用 resolveTokenTTL 统一 TTL；
// client_credentials 不签发 refresh_token、不下发 ID Token，按 RFC 6749 §4.4.3 处理。
func (o *OAuth2Service) handleClientCredentialsGrant(ctx context.Context, req *dto.OAuth2TokenRequest) (*dto.OAuth2TokenResponse, error) {
	client, err := o.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !o.supportsGrantType(client.GrantTypes, "client_credentials") {
		return nil, newOAuthError(OAuthErrUnauthorizedClient, "client does not support client_credentials grant", http.StatusBadRequest)
	}
	accessTTL, _, err := o.resolveTokenTTL(ctx, client.ID)
	if err != nil {
		return nil, err
	}
	scope := pgtype.Text{String: req.Scope, Valid: req.Scope != ""}
	audience, err := normalizeResource(req.Resource)
	if err != nil {
		return nil, err
	}
	accessToken, err := o.generateAccessToken(ctx, client.ID, 0, scope, audience, accessTTL)
	if err != nil {
		return nil, err
	}
	return &dto.OAuth2TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessTTL,
		Scope:       req.Scope,
	}, nil
}

// handleDeviceCodeGrant handles the RFC 8628 device_code grant type.
// 轮询到 approved 之后，CLI 拿 device_code 到这里换 token。与 authorization_code
// 不同：没有 redirect_uri、没有 PKCE，安全性完全建立在 device_code 的高熵（256 bit）上。
func (o *OAuth2Service) handleDeviceCodeGrant(ctx context.Context, req *dto.OAuth2TokenRequest) (*dto.OAuth2TokenResponse, error) {
	if strings.TrimSpace(req.DeviceCode) == "" {
		return nil, invalidRequest("device_code is required")
	}
	// 先原子地把 approved 翻成 consumed，成功才发 token。
	// 这样一个 device_code 只能换出一套 token：被截获的 device_code 无法重复铸币。
	rec, err := o.getQueries(ctx).ConsumeOAuth2DeviceCode(ctx, hashDeviceCode(req.DeviceCode))
	if err != nil {
		// 查无此码 或 已不是 approved（已 consumed/拒绝/过期）：统一拒绝。
		return nil, newOAuthError(OAuthErrAccessDenied, "device_code is invalid, denied, or already used", http.StatusBadRequest)
	}
	if !rec.UserID.Valid || rec.UserID.Int64 <= 0 {
		return nil, newOAuthError(OAuthErrServerError, "device authorization is missing user", http.StatusInternalServerError)
	}
	// client 认证：device flow 的 client 也要在 token 端点核对，防止跨 client 冒用。
	client, err := o.authenticateClient(ctx, rec.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !o.supportsGrantType(client.GrantTypes, "authorization_code") {
		return nil, newOAuthError(OAuthErrUnauthorizedClient, "client does not support device_code grant", http.StatusBadRequest)
	}
	accessTTL, refreshTTL, err := o.resolveTokenTTL(ctx, rec.ClientID)
	if err != nil {
		return nil, err
	}
	audience := ""
	if rec.Resource.Valid {
		audience = rec.Resource.String
	}
	scope := rec.Scope
	accessToken, err := o.generateAccessToken(ctx, rec.ClientID, rec.UserID.Int64, scope, audience, accessTTL)
	if err != nil {
		return nil, err
	}
	refreshToken, err := o.generateRefreshToken(ctx, rec.ClientID, rec.UserID.Int64, scope, audience, refreshTTL)
	if err != nil {
		return nil, err
	}
	return o.buildTokenResponse(ctx, accessToken, refreshToken, scope, accessTTL, true, rec.UserID.Int64, rec.ClientID, "")
}

// supportsGrantType checks if client supports the specified grant type
func (o *OAuth2Service) supportsGrantType(clientGrantTypes string, requiredGrantType string) bool {
	var grantTypes []string
	if err := json.Unmarshal([]byte(clientGrantTypes), &grantTypes); err != nil {
		return false
	}

	for _, grantType := range grantTypes {
		if grantType == requiredGrantType {
			return true
		}
	}
	return false
}

// RefreshToken 直接以 refresh token 字符串刷新 access token，并轮换 refresh token。
// 仅作为 service 层兜底入口保留；标准流程请走 handleRefreshTokenGrant。
func (o *OAuth2Service) RefreshToken(ctx context.Context, refreshToken string) (*dto.OAuth2TokenResponse, error) {
	queries := o.getQueries(ctx)
	token, err := queries.GetOAuth2RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, invalidGrant("invalid refresh token")
	}
	if token.Expires.Time.Before(time.Now()) {
		return nil, invalidGrant("refresh token expired")
	}
	if err := o.ensureClientEnabled(ctx, token.ClientID); err != nil {
		return nil, err
	}
	accessTTL, refreshTTL, err := o.resolveTokenTTL(ctx, token.ClientID)
	if err != nil {
		return nil, err
	}
	audience := ""
	if token.Audience.Valid {
		audience = token.Audience.String
	}
	accessToken, err := o.generateAccessToken(ctx, token.ClientID, token.UserID, token.Scope, audience, accessTTL)
	if err != nil {
		return nil, err
	}
	newRefreshToken, err := o.generateRefreshToken(ctx, token.ClientID, token.UserID, token.Scope, audience, refreshTTL)
	if err != nil {
		return nil, err
	}
	if err := queries.RevokeOAuth2RefreshToken(ctx, refreshToken); err != nil {
		slog.WarnContext(ctx, "revoke old refresh token failed", "client_id", token.ClientID, "err", err)
	}
	return o.buildTokenResponse(ctx, accessToken, newRefreshToken, token.Scope, accessTTL, false, 0, "", "")
}

// ensureClientEnabled 确保给定 client 存在且未被禁用。仅供不需要 secret 校验的场景使用。
func (o *OAuth2Service) ensureClientEnabled(ctx context.Context, clientID string) error {
	client, err := o.getQueries(ctx).GetOAuth2Client(ctx, clientID)
	if err != nil {
		return invalidClient("unknown client_id")
	}
	if !client.Enabled {
		return invalidClient("client is disabled")
	}
	return nil
}

// ValidateAccessToken 校验 access token 有效性。命中缓存时跳过数据库查询，
// 但无论是否命中都会确认签发它的 client 仍然启用——否则禁用客户端这个动作
// 对已经发出的 token 完全无效，要等它自然过期。
func (o *OAuth2Service) ValidateAccessToken(ctx context.Context, accessToken string) (*db2.AuthOauth2Token, error) {
	token := loadAccessTokenFromCache(ctx, accessToken)
	if token == nil {
		oauth2Token, err := o.getQueries(ctx).GetOAuth2Token(ctx, accessToken)
		if err != nil {
			return nil, invalidGrant("invalid or expired access token")
		}
		if time.Now().After(oauth2Token.Expires.Time) {
			return nil, invalidGrant("access token expired")
		}
		token = &oauth2Token
		storeAccessTokenToCache(ctx, token)
	}

	if err := o.ensureClientEnabled(ctx, token.ClientID); err != nil {
		revokeAccessTokenCache(ctx, accessToken)
		return nil, err
	}
	return token, nil
}

// ErrAudienceMismatch 表示 token 绑定的资源与校验方期望的资源不一致。
// 用哨兵错误而不是 OAuthError，是为了让 pkg 层能用 errors.Is 判断并转成公开错误。
var ErrAudienceMismatch = errors.New("access token was issued for a different resource")

// ValidateAccessTokenFor 在 ValidateAccessToken 之上要求 audience 匹配。
//
// 两处刻意放行，否则会把不支持 RFC 8707 的客户端和升级前签发的 token 全部打死：
//   - audience 为空：调用方自己不做资源绑定校验；
//   - token 的 audience 为空：签发时客户端没声明 resource，视为未绑定。
//
// 只有「token 绑定了资源 且 与期望不一致」才拒。
func (o *OAuth2Service) ValidateAccessTokenFor(ctx context.Context, accessToken, audience string) (*db2.AuthOauth2Token, error) {
	token, err := o.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if audience == "" || !token.Audience.Valid || token.Audience.String == "" {
		return token, nil
	}
	if token.Audience.String != audience {
		return nil, ErrAudienceMismatch
	}
	return token, nil
}

// OIDCService OIDC Service
type OIDCService struct {
	BaseService
	mu         sync.RWMutex
	privateKey *rsa.PrivateKey
	kid        string // 当前有效的私钥 kid；生成 JWT 时写入 header，使验证方能在 jwks 中匹配公钥
	keyLoaded  bool
}

// defaultOIDCService 是进程级单例；OIDC 私钥/JWK 在 mu + privateKey/kid/keyLoaded
// 上做了内存缓存，反复零值实例化会让每次 JWT 签名都多一次 DB 查询。
// 所有调用方统一通过 DefaultOIDCService() 获取，确保缓存命中。
var defaultOIDCService = &OIDCService{}

// DefaultOIDCService returns the process-wide OIDC service singleton.
func DefaultOIDCService() *OIDCService { return defaultOIDCService }

func (o *OIDCService) GetDiscoveryDocument() *dto.OIDCDiscoveryResponse {
	baseURL := gowk.BaseURL()

	return &dto.OIDCDiscoveryResponse{
		Issuer:                baseURL,
		AuthorizationEndpoint: baseURL + "/oauth2/authorize",
		TokenEndpoint:         baseURL + "/oauth2/token",
		UserInfoEndpoint:      baseURL + "/oidc/userinfo",
		JwksUri:               baseURL + "/oidc/jwks",
		ScopesSupported:       []string{"openid", "profile", "email", "phone"},
		// 当前 /oauth2/authorize 只受理 response_type=code（授权码模式）。
		// 隐式 / 混合流并未在服务端实现；这里如实声明 ["code"]，避免客户端按 RFC 8414
		// 自动协商出 id_token / token 路径再被 ValidateOAuth2AuthRequest 拒绝。
		ResponseTypesSupported:           []string{"code"},
		GrantTypesSupported:              []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		// /oauth2/token 同时接受 form 参数与 HTTP Basic 两种客户端认证方式；
		// none 供动态注册出来的 public client 使用（凭据为空，靠 PKCE 把关）。
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		// 授权端点受理 S256 与 plain 两种 PKCE 变换。
		CodeChallengeMethodsSupported: []string{"S256", "plain"},
		ClaimsSupported: []string{
			"sub", "name", "preferred_username", "email", "email_verified",
			"phone_number", "phone_number_verified", "picture", "updated_at",
		},
		EndSessionEndpoint:                        baseURL + "/oauth2/end_session",
		RevocationEndpoint:                        baseURL + "/oauth2/revoke",
		IntrospectionEndpoint:                     baseURL + "/oauth2/introspect",
		RegistrationEndpoint:                      baseURL + "/oauth2/register",
		RevocationEndpointAuthMethodsSupported:    []string{"client_secret_basic", "client_secret_post"},
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
	}
}

func (o *OIDCService) GetUserInfo(ctx context.Context, userID int64) (*dto.OIDCUserInfo, error) {
	var userService UserService
	user, err := userService.GetById(ctx, userID)
	if err != nil {
		return nil, err
	}

	// 邮箱/手机号是否"已验证"取自 users.is_verified；上层注册流程当前对两者只做单一校验，
	// 因此 OIDC 暴露的两个字段共享同一来源，避免硬编码 true 误导依赖方。
	verified := user.IsVerified.Valid && user.IsVerified.Bool
	return &dto.OIDCUserInfo{
		Sub:               fmt.Sprintf("%d", user.ID),
		Name:              user.Nickname.String,
		Email:             user.Email.String,
		EmailVerified:     verified,
		PhoneNumber:       user.Phone.String,
		PhoneVerified:     verified,
		PreferredUsername: user.Nickname.String,
		Group:             user.Group.String,
	}, nil
}

// UserInfoForScope 按 access token 授予的 scope 输出用户信息（OIDC Core §5.3.2）：
// 只返回 openid 时仅含 sub；profile / email / phone 分别解锁对应字段。
// 不做这层过滤，接入方只要拿到 access token 就能读到未申请授权的手机号与邮箱。
func (o *OIDCService) UserInfoForScope(ctx context.Context, userID int64, scope string) (*dto.OIDCUserInfo, error) {
	full, err := o.GetUserInfo(ctx, userID)
	if err != nil {
		return nil, err
	}

	hasScope := func(s string) bool {
		for _, granted := range strings.Fields(scope) {
			if granted == s {
				return true
			}
		}
		return false
	}

	filtered := &dto.OIDCUserInfo{Sub: full.Sub}
	if hasScope("profile") {
		filtered.Name = full.Name
		filtered.PreferredUsername = full.PreferredUsername
		filtered.Group = full.Group
	}
	if hasScope("email") {
		filtered.Email = full.Email
		filtered.EmailVerified = full.EmailVerified
	}
	if hasScope("phone") {
		filtered.PhoneNumber = full.PhoneNumber
		filtered.PhoneVerified = full.PhoneVerified
	}
	return filtered, nil
}

// GenerateIDToken 按 OIDC Core 1.0 §5.4 的 scope→claim 映射输出 ID Token：
//   - openid（必备） → sub/iss/aud/exp/iat/nonce/at_hash
//   - profile        → name / preferred_username / picture …
//   - email          → email / email_verified
//   - phone          → phone_number / phone_number_verified
//
// scope 为空时按"全量"输出，兼容内部 /login 等无 OAuth2 scope 的旧调用。
//
// accessToken 用于计算 at_hash（OIDC Core §3.1.3.6：从 token 端点签发的 ID Token
// 必须携带访问令牌的哈希），避免严格的验证方因缺少该声明而拒收。
func (o *OIDCService) GenerateIDToken(ctx context.Context, userID int64, clientID, nonce, scope, accessToken string, ttl int64) (string, error) {
	userInfo, err := o.GetUserInfo(ctx, userID)
	if err != nil {
		return "", err
	}

	hasScope := func(s string) bool {
		if scope == "" {
			return true
		}
		for _, sc := range strings.Fields(scope) {
			if sc == s {
				return true
			}
		}
		return false
	}

	now := time.Now().Unix()
	payload := map[string]interface{}{
		"iss": gowk.BaseURL(),
		"sub": userInfo.Sub,
		"aud": clientID,
		"exp": now + ttl,
		"iat": now,
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	if accessToken != "" {
		// at_hash = base64url(SHA-256(access_token) 的左半部分)。
		sum := sha256.Sum256([]byte(accessToken))
		payload["at_hash"] = base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
	}
	if hasScope("profile") {
		if userInfo.Name != "" {
			payload["name"] = userInfo.Name
		}
		if userInfo.PreferredUsername != "" {
			payload["preferred_username"] = userInfo.PreferredUsername
		}
	}
	if hasScope("email") && userInfo.Email != "" {
		payload["email"] = userInfo.Email
		payload["email_verified"] = userInfo.EmailVerified
	}
	if hasScope("phone") && userInfo.PhoneNumber != "" {
		payload["phone_number"] = userInfo.PhoneNumber
		payload["phone_number_verified"] = userInfo.PhoneVerified
	}

	privateKey, kid, err := o.getRSAPrivateKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get RSA private key: %w", err)
	}

	// kid 必填，验证方依赖它定位 jwks 公钥。
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal id token header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal id token payload: %w", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerEncoded + "." + payloadEncoded
	hasher := sha256.New()
	hasher.Write([]byte(signingInput))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// getRSAPrivateKey 读取/生成 JWK 私钥，并确保跨重启持久化。
// 流程：
//  1. 已加载到内存 → 直接返回；
//  2. DB 中存在最新 JWK 且含有 private_key → 解 PEM 使用；
//  3. 否则生成新 RSA-2048 密钥对，写入 DB 并缓存内存。
//
// 返回 (privateKey, kid, error)。
func (o *OIDCService) getRSAPrivateKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	o.mu.RLock()
	if o.keyLoaded && o.privateKey != nil && o.kid != "" {
		key, kid := o.privateKey, o.kid
		o.mu.RUnlock()
		return key, kid, nil
	}
	o.mu.RUnlock()

	o.mu.Lock()
	defer o.mu.Unlock()

	if o.keyLoaded && o.privateKey != nil && o.kid != "" {
		return o.privateKey, o.kid, nil
	}

	queries := o.getQueries(ctx)
	if latest, err := queries.GetLatestOIDCJwk(ctx); err == nil && latest.PrivateKey != "" {
		if key, perr := parseRSAPrivateKeyPEM(latest.PrivateKey); perr == nil {
			o.privateKey = key
			o.kid = latest.Kid
			o.keyLoaded = true
			return o.privateKey, o.kid, nil
		} else {
			slog.WarnContext(ctx, "failed to parse stored JWK private key, generating new one", "err", perr, "kid", latest.Kid)
		}
	}

	key, kid, err := o.createAndStoreJWK(ctx, queries)
	if err != nil {
		return nil, "", err
	}
	o.privateKey = key
	o.kid = kid
	o.keyLoaded = true
	return key, kid, nil
}

// createAndStoreJWK 生成新 RSA 密钥对并将公钥 n/e + PEM 私钥写入 auth_oidc_jwk。
func (o *OIDCService) createAndStoreJWK(ctx context.Context, queries *db2.Queries) (*rsa.PrivateKey, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate RSA key: %w", err)
	}
	privPEM := encodeRSAPrivateKeyPEM(priv)
	kid := gowk.GenerateRandomString(16)
	id := gowk.GenerateRandomString(32)

	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())

	if _, dbErr := queries.CreateOIDCJwk(ctx, db2.CreateOIDCJwkParams{
		ID:         id,
		Kid:        kid,
		Kty:        "RSA",
		Use:        "sig",
		Alg:        "RS256",
		N:          n,
		E:          e,
		PrivateKey: privPEM,
	}); dbErr != nil {
		// 持久化失败也让服务可用，但警告：下次重启仍会生成新 key，造成 JWT 不可验证；上线前应排查 DB 问题。
		slog.WarnContext(ctx, "failed to persist JWK to database; using in-memory key only", "err", dbErr, "kid", kid)
	}
	return priv, kid, nil
}

func encodeRSAPrivateKeyPEM(key *rsa.PrivateKey) string {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return string(pem.EncodeToMemory(block))
}

func parseRSAPrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("stored key is not RSA")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// GetJwks 从数据库读取 JWK，只暴露公钥字段（n/e），不暴露 private_key。
// 使用调用方 ctx，确保查询能被请求级别的取消/超时正确传播。
func (o *OIDCService) GetJwks(ctx context.Context) (*dto.OIDCJwksResponse, error) {
	// 数据库不可用时 gowk.DB 返回 nil，db2.New(nil) 后续查询会空指针 panic。
	// 这里显式返回错误，让调用方回 503；返回空 keys 会让客户端误判"密钥集为空"。
	if gowk.DB(ctx) == nil {
		return nil, errors.New("database unavailable")
	}
	jwks, err := o.getQueries(ctx).GetActiveOIDCJwks(ctx)
	if err != nil {
		slog.WarnContext(ctx, "list jwks failed", "err", err)
		return nil, err
	}

	keys := make([]dto.OIDCJwk, 0, len(jwks))
	for _, jwk := range jwks {
		keys = append(keys, dto.OIDCJwk{
			Kty: jwk.Kty,
			Use: jwk.Use,
			Kid: jwk.Kid,
			N:   jwk.N,
			E:   jwk.E,
			Alg: jwk.Alg,
		})
	}
	return &dto.OIDCJwksResponse{Keys: keys}, nil
}

// phoneRe 提前编译；regexp.MatchString 每次重编译会显著影响登录热路径。
var phoneRe = regexp.MustCompile(`^1[3-9]\d{9}$`)

// isValidPhone 基本中国大陆手机号校验。
func isValidPhone(phone string) bool {
	return phoneRe.MatchString(phone)
}

// OAuth2ClientService handles OAuth2 client management.
// 不缓存 *db2.Queries：每次调用通过 BaseService.getQueries(ctx) 按需取，
// 这样零值实例（var s OAuth2ClientService）也能正常工作。
type OAuth2ClientService struct {
	BaseService
}

func NewOAuth2ClientService(_ context.Context) *OAuth2ClientService {
	return &OAuth2ClientService{}
}

// CreateOAuth2Client creates a new OAuth2 client
func (s *OAuth2ClientService) CreateOAuth2Client(ctx context.Context, params *dto.OAuth2ClientCreateParams) (*dto.OAuth2ClientResponse, error) {
	// Gin binding validation already handles all validation rules via binding tags
	// No additional manual validation needed

	// Convert arrays to JSON
	redirectURIsJSON, err := json.Marshal(params.RedirectURIs)
	if err != nil {
		return nil, gowk.NewError("invalid redirect URIs format")
	}
	scopesJSON, err := json.Marshal(params.Scopes)
	if err != nil {
		return nil, gowk.NewError("invalid scopes format")
	}
	grantTypesJSON, err := json.Marshal(params.GrantTypes)
	if err != nil {
		return nil, gowk.NewError("invalid grant types format")
	}

	// Set default TTL values
	accessTokenTTL := params.AccessTokenTTL
	if accessTokenTTL == 0 {
		accessTokenTTL = 3600 // 1 hour default
	}
	refreshTokenTTL := params.RefreshTokenTTL
	if refreshTokenTTL == 0 {
		refreshTokenTTL = 2592000 // 30 days default
	}

	clientID, err := s.resolveClientID(ctx, params.ID)
	if err != nil {
		return nil, err
	}

	o, err := s.getQueries(ctx).CreateOAuth2Client(ctx, db2.CreateOAuth2ClientParams{
		ID:              clientID,
		Name:            params.Name,
		Secret:          gowk.GenerateRandomString(64),
		RedirectUris:    string(redirectURIsJSON),
		Scopes:          string(scopesJSON),
		GrantTypes:      string(grantTypesJSON),
		AccessTokenTtl:  accessTokenTTL,
		RefreshTokenTtl: refreshTokenTTL,
		Created:         pgtype.Timestamptz{Time: time.Now(), Valid: true},
		Updated:         pgtype.Timestamptz{Time: time.Now(), Valid: true},
		Enabled:         true, // true = active
	})
	if err != nil {
		return nil, err
	}
	return buildOAuth2ClientResponseWithSecret(o, true), nil
}

// oauth2ClientIDPattern 限定可自定义的 client_id 字符集：出现在 URL 查询参数
// 与第三方配置里，只允许不会引起转义歧义的字符。
var oauth2ClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// resolveClientID 优先使用调用方指定的 client_id（便于接入方配置易读名字），
// 留空时生成随机值；指定值必须符合字符集且未被占用。
func (s *OAuth2ClientService) resolveClientID(ctx context.Context, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return gowk.GenerateRandomString(32), nil
	}
	if !oauth2ClientIDPattern.MatchString(requested) {
		return "", gowk.NewError("client_id 只能包含字母、数字、点、下划线和连字符，长度 1-64")
	}
	if _, err := s.getQueries(ctx).GetOAuth2Client(ctx, requested); err == nil {
		return "", gowk.NewError("client_id 已存在")
	}
	return requested, nil
}

// UpdateOAuth2Client 真正将 params 写入数据库；未在 params 中提供的字段保持不变。
// - 空字符串字段（Name/Secret 等）视为“不修改”；
// - TTL 字段 <= 0 视为“不修改”；
// - Enabled 为指针，nil 视为“不修改”，否则显式覆盖。
func (s *OAuth2ClientService) UpdateOAuth2Client(ctx context.Context, params *dto.OAuth2ClientUpdateParams) (*dto.OAuth2ClientResponse, error) {
	if params == nil || params.ID == "" {
		return nil, gowk.NewError("client ID is required")
	}
	if _, err := s.getQueries(ctx).GetOAuth2Client(ctx, params.ID); err != nil {
		return nil, gowk.NewError("client not found")
	}

	redirectURIs, err := marshalJSONArray(params.RedirectURIs)
	if err != nil {
		return nil, gowk.NewError("invalid redirect_uris")
	}
	scopes, err := marshalJSONArray(params.Scopes)
	if err != nil {
		return nil, gowk.NewError("invalid scopes")
	}
	grantTypes, err := marshalJSONArray(params.GrantTypes)
	if err != nil {
		return nil, gowk.NewError("invalid grant_types")
	}

	enabled := pgtype.Bool{}
	if params.Enabled != nil {
		enabled.Bool = *params.Enabled
		enabled.Valid = true
	}

	updated, err := s.getQueries(ctx).UpdateOAuth2Client(ctx, db2.UpdateOAuth2ClientParams{
		ID:              params.ID,
		Name:            params.Name,
		Secret:          params.Secret,
		RedirectUris:    redirectURIs,
		Scopes:          scopes,
		GrantTypes:      grantTypes,
		AccessTokenTtl:  params.AccessTokenTTL,
		RefreshTokenTtl: params.RefreshTokenTTL,
		Enabled:         enabled,
	})
	if err != nil {
		return nil, fmt.Errorf("update oauth2 client: %w", err)
	}
	return buildOAuth2ClientResponse(updated), nil
}

// RegenerateClientSecret 为指定 client 生成新 secret 并落库，返回更新后的 client 响应。
func (s *OAuth2ClientService) RegenerateClientSecret(ctx context.Context, clientID, newSecret string) (*dto.OAuth2ClientResponse, error) {
	if clientID == "" {
		return nil, gowk.NewError("client ID is required")
	}
	if newSecret == "" {
		return nil, gowk.NewError("new secret is required")
	}
	updated, err := s.getQueries(ctx).UpdateOAuth2ClientSecret(ctx, db2.UpdateOAuth2ClientSecretParams{
		ID:     clientID,
		Secret: newSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("regenerate client secret: %w", err)
	}
	return buildOAuth2ClientResponseWithSecret(updated, true), nil
}

// marshalJSONArray 将字符串切片序列化为 JSON；切片为空（nil / len 0）时返回空串以触发 SQL 侧的 NULLIF 不覆盖语义。
func marshalJSONArray(items []string) (string, error) {
	if len(items) == 0 {
		return "", nil
	}
	b, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DeleteOAuth2Client soft deletes an OAuth2 client (sets status to disabled)
func (s *OAuth2ClientService) DisableOAuth2Client(ctx context.Context, clientID string) error {
	return s.getQueries(ctx).DisableOAuth2Client(ctx, clientID)
}

// GetOAuth2Client retrieves an OAuth2 client by ID
func (s *OAuth2ClientService) GetOAuth2Client(ctx context.Context, clientID string) (*dto.OAuth2ClientResponse, error) {
	// Gin binding validation already handles all validation rules via binding tags
	// No additional manual validation needed

	// Use SQLC generated method
	queries := s.getQueries(ctx)
	client, err := queries.GetOAuth2Client(ctx, clientID)
	if err != nil {
		return nil, gowk.NewError("client not found")
	}
	// Convert database model to DTO
	return buildOAuth2ClientResponse(client), nil
}

// ListOAuth2Clients lists OAuth2 clients with pagination and filtering
func (s *OAuth2ClientService) ListOAuth2Clients(ctx context.Context) ([]*dto.OAuth2ClientResponse, error) {
	os, err := s.getQueries(ctx).ListOAuth2Client(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]*dto.OAuth2ClientResponse, 0, len(os))
	for _, o := range os {
		res = append(res, buildOAuth2ClientResponse(o))
	}
	return res, nil
}
