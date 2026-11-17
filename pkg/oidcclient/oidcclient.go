// Package oidcclient 封装接入 Auth 所需的 OIDC 客户端动作：
// 授权跳转、授权码换 token、刷新 token、校验 ID Token、读取 userinfo。
//
// 它只做协议调用与结果整形，协议实现来自 coreos/go-oidc 与 golang.org/x/oauth2。
//
// 使用时最容易踩的两个点：
//   - Issuer 必须与被接入 Auth 的 gowk.BaseURL() 完全一致（含协议、端口、无尾斜杠）。
//     ID Token 的 iss 声明与它比对，只要不一致，校验必然失败。
//   - AccessToken 是不透明字符串，不能自行解析，取用户信息只能调 UserInfo。
package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrMissingIssuer       = errors.New("oidcclient: Issuer is required")
	ErrMissingClientID     = errors.New("oidcclient: ClientID is required")
	ErrMissingRedirectURL  = errors.New("oidcclient: RedirectURL is required")
	ErrMissingCode         = errors.New("oidcclient: authorization code is empty")
	ErrMissingIDToken      = errors.New("oidcclient: id_token is empty")
	ErrMissingAccessToken  = errors.New("oidcclient: access token is empty")
	ErrMissingRefreshToken = errors.New("oidcclient: refresh token is empty")
	ErrNonceMismatch       = errors.New("oidcclient: id_token nonce does not match the one sent in the authorization request")
)

// Config 是对接一个 Auth 实例所需的全部配置。
type Config struct {
	// Issuer 是被接入 Auth 的对外基础地址，例如 https://auth.example.com。
	// 必须与该实例 gowk.BaseURL() 的返回值完全一致。
	Issuer string
	// ClientID / ClientSecret 是 Auth 中登记的 OAuth2 客户端凭据。
	// ClientSecret 留空表示 public client，此时必须使用 PKCE。
	ClientID     string
	ClientSecret string
	// RedirectURL 必须与 Auth 中登记的回调地址一致。
	RedirectURL string
	// Scopes 留空时默认 openid profile email。
	// 不含 openid 时不会返回 ID Token。
	Scopes []string
	// HTTPClient 留空使用 http.DefaultClient。
	HTTPClient *http.Client
}

const defaultScope = "openid profile email"

// Client 是并发安全的，创建一次即可全局复用。
type Client struct {
	oauth    *oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	http     *http.Client
	endpoint Endpoints
	scopes   []string
}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// New 拉取一次 discovery 文档并构建客户端。
func New(ctx context.Context, cfg Config) (*Client, error) {
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if cfg.Issuer == "" {
		return nil, ErrMissingIssuer
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, ErrMissingClientID
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, ErrMissingRedirectURL
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = strings.Fields(defaultScope)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	ctx = oidc.ClientContext(ctx, httpClient)

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidcclient: discovery %s failed: %w", cfg.Issuer, err)
	}

	var doc discoveryDocument
	if err := provider.Claims(&doc); err != nil {
		return nil, fmt.Errorf("oidcclient: decode discovery document failed: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       scopes,
		Endpoint:     provider.Endpoint(),
	}
	// 明确用 client_secret_basic，避免 oauth2 自动探测先发一次失败请求，
	// 把只能使用一次的授权码白白浪费掉。Auth 同时支持 basic 与 post 两种方式。
	oauthConfig.Endpoint.AuthStyle = oauth2.AuthStyleInHeader

	return &Client{
		oauth:    oauthConfig,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		http:     httpClient,
		scopes:   scopes,
		endpoint: Endpoints{
			Issuer:        firstNonEmpty(doc.Issuer, cfg.Issuer),
			Authorization: firstNonEmpty(doc.AuthorizationEndpoint, provider.Endpoint().AuthURL),
			Token:         firstNonEmpty(doc.TokenEndpoint, provider.Endpoint().TokenURL),
			UserInfo:      doc.UserInfoEndpoint,
			JWKS:          doc.JWKSURI,
		},
	}, nil
}

// AuthURLOptions 控制授权跳转的附加参数。
type AuthURLOptions struct {
	// Nonce 会写入 ID Token，回调时用 VerifyIDToken 传入同一个值比对。
	Nonce string
	// DisablePKCE 关闭 PKCE。public client（无 ClientSecret）不应关闭。
	DisablePKCE bool
	// Extra 追加自定义查询参数，例如 prompt=login。
	Extra map[string]string
}

// AuthCodeURL 生成授权跳转地址，并返回本次 PKCE 的 code verifier。
// verifier 必须随会话保存，回调时交给 Exchange；DisablePKCE 为真时返回空串。
func (c *Client) AuthCodeURL(state string, opt AuthURLOptions) (authURL string, codeVerifier string) {
	opts := make([]oauth2.AuthCodeOption, 0, 3+len(opt.Extra))
	if !opt.DisablePKCE {
		codeVerifier = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(codeVerifier))
	}
	if opt.Nonce != "" {
		opts = append(opts, oidc.Nonce(opt.Nonce))
	}
	for key, value := range opt.Extra {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	return c.oauth.AuthCodeURL(state, opts...), codeVerifier
}

// Exchange 用授权码换取 token。codeVerifier 是 AuthCodeURL 的返回值，
// 未启用 PKCE 时传空串。
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string) (*Token, error) {
	if strings.TrimSpace(code) == "" {
		return nil, ErrMissingCode
	}
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if codeVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(codeVerifier))
	}
	token, err := c.oauth.Exchange(c.context(ctx), code, opts...)
	if err != nil {
		return nil, fmt.Errorf("oidcclient: exchange authorization code failed: %w", err)
	}
	return fromOAuth2Token(token), nil
}

// Refresh 用 refresh token 换一组新凭据。
// Auth 会轮转 refresh token，调用方必须用返回值里的 RefreshToken 覆盖旧值。
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Token, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, ErrMissingRefreshToken
	}
	source := c.oauth.TokenSource(c.context(ctx), &oauth2.Token{RefreshToken: refreshToken})
	token, err := source.Token()
	if err != nil {
		return nil, fmt.Errorf("oidcclient: refresh token failed: %w", err)
	}
	return fromOAuth2Token(token), nil
}

// UserInfo 用 access token 读取用户声明。access token 是不透明字符串，只能交给服务端解析。
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, ErrMissingAccessToken
	}
	info, err := c.provider.UserInfo(c.context(ctx), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken}))
	if err != nil {
		return nil, fmt.Errorf("oidcclient: fetch userinfo failed: %w", err)
	}

	out := &UserInfo{Raw: map[string]any{}}
	if err := info.Claims(&out.Claims); err != nil {
		return nil, fmt.Errorf("oidcclient: decode userinfo claims failed: %w", err)
	}
	if err := info.Claims(&out.Raw); err != nil {
		return nil, fmt.Errorf("oidcclient: decode raw userinfo failed: %w", err)
	}
	return out, nil
}

// VerifyIDToken 校验 ID Token 的签名、iss、aud 与有效期，并比对 nonce。
// nonce 传空串表示不校验。
func (c *Client) VerifyIDToken(ctx context.Context, rawIDToken, nonce string) (*IDToken, error) {
	if strings.TrimSpace(rawIDToken) == "" {
		return nil, ErrMissingIDToken
	}
	token, err := c.verifier.Verify(c.context(ctx), rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidcclient: verify id_token failed: %w", err)
	}
	if nonce != "" && token.Nonce != nonce {
		return nil, ErrNonceMismatch
	}

	out := &IDToken{
		Issuer:   token.Issuer,
		Audience: token.Audience,
		Expiry:   token.Expiry,
		IssuedAt: token.IssuedAt,
		Nonce:    token.Nonce,
		Raw:      map[string]any{},
	}
	if err := token.Claims(&out.Claims); err != nil {
		return nil, fmt.Errorf("oidcclient: decode id_token claims failed: %w", err)
	}
	if err := token.Claims(&out.Raw); err != nil {
		return nil, fmt.Errorf("oidcclient: decode raw id_token failed: %w", err)
	}
	return out, nil
}

// Scopes 返回本次客户端申请的 scope。
func (c *Client) Scopes() []string { return append([]string(nil), c.scopes...) }

// Endpoints 返回 discovery 中声明的端点，便于日志与自查。
func (c *Client) Endpoints() Endpoints { return c.endpoint }

func (c *Client) context(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, c.http)
}

func fromOAuth2Token(token *oauth2.Token) *Token {
	out := &Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}
	if idToken, ok := token.Extra("id_token").(string); ok {
		out.IDToken = idToken
	}
	if scope, ok := token.Extra("scope").(string); ok {
		out.Scope = scope
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
