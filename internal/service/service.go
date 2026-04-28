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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/iautre/auth/internal/config"
	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/auth/pkg/util"
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

// Login 登录
func (u *UserService) Login(ctx context.Context, params *dto.LoginParams) (db2.AuthUser, error) {
	// Get user by phone (for now, only phone is supported)
	user, err := u.GetByPhone(ctx, params.Account)
	if err != nil {
		return db2.AuthUser{}, gowk.NewError("user not found")
	}

	// Check user status
	if !user.Enabled {
		return db2.AuthUser{}, gowk.NewError("account is disabled")
	}

	// Verify OTP code
	var otp util.OTP
	if !otp.CheckCode(user.Secret.String, params.Code) {
		return db2.AuthUser{}, gowk.NewError("invalid verification code")
	}

	// Update login info (best-effort：失败不阻断登录，但需要记录便于排查)
	if err := u.UpdateLoginInfo(ctx, user.ID); err != nil {
		slog.WarnContext(ctx, "update login info failed", "user_id", user.ID, "err", err)
	}

	return user, nil
}

// GetByAccount retrieves user by phone or email (simplified version)
func (u *UserService) GetByAccount(ctx context.Context, account string) (db2.AuthUser, error) {
	if account == "" {
		return db2.AuthUser{}, gowk.NewError("account cannot be empty")
	}

	// For now, just use phone lookup
	// Email support would require database query updates
	return u.GetByPhone(ctx, account)
}

// GetByEmail retrieves user by email
func (u *UserService) GetByEmail(ctx context.Context, email string) (db2.AuthUser, error) {
	if email == "" {
		return db2.AuthUser{}, gowk.NewError("email cannot be empty")
	}

	// For now, return empty user as placeholder
	// This would require database query implementation with proper email field
	return db2.AuthUser{}, gowk.NewError("email login not yet implemented")
}

// ResetOTPCode 重新生成用户 OTP 秘钥并写库，返回新秘钥。
func (u *UserService) ResetOTPCode(ctx context.Context, userId int64) (string, error) {
	if userId <= 0 {
		return "", gowk.NewError("invalid user ID")
	}
	newSecret, err := util.GenerateOTPSecret()
	if err != nil {
		return "", fmt.Errorf("generate otp secret: %w", err)
	}
	if err := u.getQueries(ctx).UpdateUserSecret(ctx, db2.UpdateUserSecretParams{
		ID:     userId,
		Secret: pgtype.Text{String: newSecret, Valid: true},
	}); err != nil {
		return "", fmt.Errorf("update user secret: %w", err)
	}
	return newSecret, nil
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
func (o *OAuth2Service) GenerateAuthorizationCode(ctx context.Context, clientID string, userID int64, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) (string, error) {
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "plain"
		}
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			return "", gowk.NewError("unsupported code_challenge_method")
		}
	} else if codeChallengeMethod != "" {
		return "", gowk.NewError("code_challenge_method requires code_challenge")
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
		Expires:             pgtype.Timestamptz{Time: expires, Valid: true},
	}

	if _, err := o.getQueries(ctx).CreateOAuth2AuthorizationCode(ctx, authCode); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

func (o *OAuth2Service) ValidateOAuth2AuthRequest(ctx context.Context, req *dto.OAuth2AuthRequest) (*db2.AuthOauth2Client, error) {
	client, err := o.getQueries(ctx).GetOAuth2Client(ctx, req.ClientID)
	if err != nil {
		return nil, gowk.NewError("invalid client_id")
	}
	if !client.Enabled {
		return nil, gowk.NewError("client is disabled")
	}

	var redirectURIs []string
	if err := json.Unmarshal([]byte(client.RedirectUris), &redirectURIs); err != nil {
		return nil, gowk.NewError("invalid client configuration")
	}

	validRedirectURI := false
	for _, uri := range redirectURIs {
		if uri == req.RedirectURI {
			validRedirectURI = true
			break
		}
	}
	if !validRedirectURI {
		return nil, gowk.NewError("invalid redirect_uri")
	}
	return &client, nil
}

// ValidateAuthorizationCode 取出并校验授权码。
// redirectURI 用于回放期 redirect_uri 强一致校验（RFC 6749 §4.1.3）：
// 颁发授权码时存入了 redirect_uri，则换 token 时必须一字不差地传回。
func (o *OAuth2Service) ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI string) (*db2.AuthOauth2AuthorizationCode, error) {
	queries := o.getQueries(ctx)

	authCode, err := queries.GetOAuth2AuthorizationCode(ctx, code)
	if err != nil {
		return nil, gowk.NewError("authorization code not found")
	}

	if authCode.ClientID != clientID {
		return nil, gowk.NewError("client ID mismatch")
	}

	if authCode.Expires.Time.Before(time.Now()) {
		return nil, gowk.NewError("authorization code expired")
	}

	// redirect_uri 必须与授权阶段一致；允许未绑定时跳过比对（罕见场景，保守兼容）。
	if authCode.RedirectUri.Valid && authCode.RedirectUri.String != "" {
		if redirectURI == "" || authCode.RedirectUri.String != redirectURI {
			return nil, gowk.NewError("redirect_uri mismatch")
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
		return nil, gowk.NewError("authorization code already used or expired")
	}
	return &authCode, nil
}

// 默认 TTL：仅在 client 配置缺失时兜底。
const (
	defaultAccessTokenTTL  = int64(3600)           // 1h
	defaultRefreshTokenTTL = int64(30 * 24 * 3600) // 30d
)

func DefaultAccessTokenTTL() int64 { return defaultAccessTokenTTL }

// resolveTokenTTL 拿到 client 的 TTL；client 不存在时回退到默认值。
func (o *OAuth2Service) resolveTokenTTL(ctx context.Context, clientID string) (accessTTL, refreshTTL int64) {
	client, err := o.getQueries(ctx).GetOAuth2Client(ctx, clientID)
	if err != nil || client.AccessTokenTtl <= 0 {
		accessTTL = defaultAccessTokenTTL
	} else {
		accessTTL = client.AccessTokenTtl
	}
	if err != nil || client.RefreshTokenTtl <= 0 {
		refreshTTL = defaultRefreshTokenTTL
	} else {
		refreshTTL = client.RefreshTokenTtl
	}
	return
}

// generateAccessToken 生成并落库一枚 access token，返回 token 字符串。
func (o *OAuth2Service) generateAccessToken(ctx context.Context, clientID string, userID int64, scope pgtype.Text, ttl int64) (string, error) {
	accessToken := gowk.GenerateRandomString(64)
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	if _, err := o.getQueries(ctx).CreateOAuth2Token(ctx, db2.CreateOAuth2TokenParams{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ClientID:    clientID,
		UserID:      userID,
		Scope:       scope,
		Expires:     pgtype.Timestamptz{Time: expires, Valid: true},
	}); err != nil {
		return "", fmt.Errorf("failed to store access token: %w", err)
	}
	return accessToken, nil
}

// generateRefreshToken 生成并落库一枚 refresh token，返回 token 字符串。
func (o *OAuth2Service) generateRefreshToken(ctx context.Context, clientID string, userID int64, scope pgtype.Text, ttl int64) (string, error) {
	refreshToken := gowk.GenerateRandomString(64)
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	if _, err := o.getQueries(ctx).CreateOAuth2RefreshToken(ctx, db2.CreateOAuth2RefreshTokenParams{
		RefreshToken: refreshToken,
		ClientID:     clientID,
		UserID:       userID,
		Scope:        scope,
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
		idToken, err := DefaultOIDCService().GenerateIDToken(ctx, userID, clientID, nonce, scope.String, accessTTL)
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
	default:
		return nil, gowk.NewError("unsupported grant_type: " + req.GrantType)
	}
}

// handleAuthorizationCodeGrant handles authorization_code grant type
func (o *OAuth2Service) handleAuthorizationCodeGrant(ctx context.Context, req *dto.OAuth2TokenRequest) (*dto.OAuth2TokenResponse, error) {
	client, err := o.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !o.supportsGrantType(client.GrantTypes, "authorization_code") {
		return nil, gowk.NewError("client does not support authorization_code grant")
	}
	authCode, err := o.ValidateAuthorizationCode(ctx, req.Code, req.ClientID, req.RedirectURI)
	if err != nil {
		return nil, err
	}
	if err := o.verifyPKCE(authCode, req.CodeVerifier); err != nil {
		return nil, err
	}
	authCode, err = o.ConsumeAuthorizationCode(ctx, req.Code, req.ClientID)
	if err != nil {
		return nil, err
	}
	accessTTL, refreshTTL := o.resolveTokenTTL(ctx, req.ClientID)
	accessToken, err := o.generateAccessToken(ctx, authCode.ClientID, authCode.UserID, authCode.Scope, accessTTL)
	if err != nil {
		return nil, err
	}
	refreshToken, err := o.generateRefreshToken(ctx, authCode.ClientID, authCode.UserID, authCode.Scope, refreshTTL)
	if err != nil {
		return nil, err
	}
	return o.buildTokenResponse(ctx, accessToken, refreshToken, authCode.Scope, accessTTL, true, authCode.UserID, authCode.ClientID, authCode.Nonce.String)
}

// handleRefreshTokenGrant handles refresh_token grant type.
// 采用 refresh token rotation：换 access token 时同时签发新 refresh token，并回收旧的，避免数据库孤儿、降低重放风险。
func (o *OAuth2Service) handleRefreshTokenGrant(ctx context.Context, req *dto.OAuth2TokenRequest) (*dto.OAuth2TokenResponse, error) {
	queries := o.getQueries(ctx)
	token, err := queries.GetOAuth2RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, gowk.NewError("invalid or expired refresh token")
	}
	if time.Now().After(token.Expires.Time) {
		return nil, gowk.NewError("refresh token expired")
	}
	// refresh 流程也必须验证 client。req.ClientID 若提供则需与 token 匹配，避免跨 client 串用。
	if req.ClientID != "" && req.ClientID != token.ClientID {
		return nil, gowk.NewError("client_id does not match refresh token")
	}
	client, err := o.authenticateClient(ctx, token.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !o.supportsGrantType(client.GrantTypes, "refresh_token") {
		return nil, gowk.NewError("client does not support refresh_token grant")
	}
	accessTTL, refreshTTL := o.resolveTokenTTL(ctx, token.ClientID)
	accessToken, err := o.generateAccessToken(ctx, token.ClientID, token.UserID, token.Scope, accessTTL)
	if err != nil {
		return nil, err
	}
	newRefreshToken, err := o.generateRefreshToken(ctx, token.ClientID, token.UserID, token.Scope, refreshTTL)
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
		return nil, gowk.NewError("client_id is required")
	}
	client, err := o.getQueries(ctx).GetOAuth2Client(ctx, clientID)
	if err != nil {
		return nil, gowk.NewError("invalid client_id")
	}
	if !client.Enabled {
		return nil, gowk.NewError("client is disabled")
	}
	if client.Secret != "" {
		if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
			return nil, gowk.NewError("invalid client credentials")
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
			return gowk.NewError("code_verifier provided but authorization code was not bound to PKCE")
		}
		return nil
	}
	if codeVerifier == "" {
		return gowk.NewError("code_verifier is required")
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
		return gowk.NewError("unsupported code_challenge_method")
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(authCode.CodeChallenge.String)) != 1 {
		return gowk.NewError("invalid code_verifier")
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
		return nil, gowk.NewError("client does not support client_credentials grant")
	}
	accessTTL, _ := o.resolveTokenTTL(ctx, client.ID)
	scope := pgtype.Text{String: req.Scope, Valid: req.Scope != ""}
	accessToken, err := o.generateAccessToken(ctx, client.ID, 0, scope, accessTTL)
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
		return nil, gowk.NewError("invalid refresh token")
	}
	if token.Expires.Time.Before(time.Now()) {
		return nil, gowk.NewError("refresh token expired")
	}
	if err := o.ensureClientEnabled(ctx, token.ClientID); err != nil {
		return nil, err
	}
	accessTTL, refreshTTL := o.resolveTokenTTL(ctx, token.ClientID)
	accessToken, err := o.generateAccessToken(ctx, token.ClientID, token.UserID, token.Scope, accessTTL)
	if err != nil {
		return nil, err
	}
	newRefreshToken, err := o.generateRefreshToken(ctx, token.ClientID, token.UserID, token.Scope, refreshTTL)
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
		return gowk.NewError("invalid client_id")
	}
	if !client.Enabled {
		return gowk.NewError("client is disabled")
	}
	return nil
}

// ValidateAccessToken validates access token from database
func (o *OAuth2Service) ValidateAccessToken(ctx context.Context, accessToken string) (*db2.AuthOauth2Token, error) {
	// Get token from database
	queries := o.getQueries(ctx)
	oauth2Token, err := queries.GetOAuth2Token(ctx, accessToken)
	if err != nil {
		return nil, gowk.NewError("invalid or expired access token")
	}

	// Check if token is expired
	if time.Now().After(oauth2Token.Expires.Time) {
		return nil, gowk.NewError("access token expired")
	}

	return &oauth2Token, nil
}

// SSO Service
type SSOService struct{}

// ErrSSONotImplemented 表示第三方 SSO 登录接口尚未实现。Handler 层应据此返回 501。
var ErrSSONotImplemented = errors.New("sso login is not implemented")

// LoginWithProvider 当前未实现真实的第三方 SSO 登录。
// 接入真实 provider（Google/GitHub/WeChat 等）时，需要：
//  1. 使用 provider 的 OAuth2 token endpoint 换取 access_token；
//  2. 使用该 access_token 调用 provider userinfo 获取唯一身份标识；
//  3. 在 auth_user 表匹配/建联本地账号，并签发本地会话 token（gowk.Login）。
//
// 在未实现前拒绝，避免被滥用签发无主 token。
func (s *SSOService) LoginWithProvider(ctx context.Context, req *dto.SSOLoginRequest) (*dto.SSOLoginResponse, error) {
	return nil, ErrSSONotImplemented
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
	// Get normalized base URL
	baseURL := gowk.BaseURL()

	// Get normalized API prefix
	prefix := config.AuthAPIPrefix()

	// Build endpoints safely
	buildEndpoint := func(path string) string {
		if prefix != "" {
			return baseURL + prefix + path
		}
		return baseURL + path
	}

	return &dto.OIDCDiscoveryResponse{
		Issuer:                baseURL,
		AuthorizationEndpoint: buildEndpoint("/oauth2/auth"),
		TokenEndpoint:         buildEndpoint("/oauth2/token"),
		UserInfoEndpoint:      buildEndpoint("/oidc/userinfo"),
		JwksUri:               buildEndpoint("/oidc/jwks"),
		ScopesSupported:       []string{"openid", "profile", "email", "phone"},
		// 当前 /oauth2/auth 只受理 response_type=code（授权码模式）。
		// 隐式 / 混合流并未在服务端实现；这里如实声明 ["code"]，避免客户端按 RFC 8414
		// 自动协商出 id_token / token 路径再被 ValidateOAuth2AuthRequest 拒绝。
		ResponseTypesSupported:           []string{"code"},
		GrantTypesSupported:              []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
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
	}, nil
}

// GenerateIDToken 按 OIDC Core 1.0 §5.4 的 scope→claim 映射输出 ID Token：
//   - openid（必备） → sub/iss/aud/exp/iat/nonce
//   - profile        → name / preferred_username / picture …
//   - email          → email / email_verified
//   - phone          → phone_number / phone_number_verified
//
// scope 为空时按"全量"输出，兼容内部 /login 等无 OAuth2 scope 的旧调用。
func (o *OIDCService) GenerateIDToken(ctx context.Context, userID int64, clientID, nonce, scope string, ttl int64) (string, error) {
	userInfo, err := o.GetUserInfo(ctx, userID)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
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
func (o *OIDCService) GetJwks(ctx context.Context) *dto.OIDCJwksResponse {
	jwks, err := o.getQueries(ctx).GetActiveOIDCJwks(ctx)
	if err != nil {
		slog.WarnContext(ctx, "list jwks failed", "err", err)
		return &dto.OIDCJwksResponse{Keys: []dto.OIDCJwk{}}
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
	return &dto.OIDCJwksResponse{Keys: keys}
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

	// For now, return placeholder response
	// This would require database query implementation
	o, err := s.getQueries(ctx).CreateOAuth2Client(ctx, db2.CreateOAuth2ClientParams{
		ID:              gowk.GenerateRandomString(32),
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
	return dto.BuildOAuth2ClientResponseWithSecret(o, true), nil
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
	return dto.BuildOAuth2ClientResponse(updated), nil
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
	return dto.BuildOAuth2ClientResponseWithSecret(updated, true), nil
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
	return dto.BuildOAuth2ClientResponse(client), nil
}

// ListOAuth2Clients lists OAuth2 clients with pagination and filtering
func (s *OAuth2ClientService) ListOAuth2Clients(ctx context.Context) ([]*dto.OAuth2ClientResponse, error) {
	os, err := s.getQueries(ctx).ListOAuth2Client(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]*dto.OAuth2ClientResponse, 0, len(os))
	for _, o := range os {
		res = append(res, dto.BuildOAuth2ClientResponse(o))
	}
	return res, nil
}
