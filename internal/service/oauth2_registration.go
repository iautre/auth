package service

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgtype"
)

// DefaultAuthorizeScope 是授权请求未携带 scope 时的默认集合。
// 部分 MCP 客户端不传 scope，缺省给它身份相关的最小集合，而不是直接拒绝。
const DefaultAuthorizeScope = "openid profile email"

// registrationScopes 是动态注册允许申请的 scope 上限。
// 刻意不含 phone：第三方客户端没有理由读到与身份无关的字段。
var registrationScopes = []string{"openid", "profile", "email"}

// 动态注册只支持授权码 + 刷新；client_credentials 是给机器身份的，
// 而 MCP 授权要落到具体用户，因此不接受。
var registrationGrantTypes = []string{"authorization_code", "refresh_token"}

// RFC 7591 §3.2.2 的错误码。
const (
	RegistrationErrInvalidRedirectURI    = "invalid_redirect_uri"
	RegistrationErrInvalidClientMetadata = "invalid_client_metadata"
)

// RegistrationError 携带 RFC 7591 定义的错误码，供 handler 原样输出。
type RegistrationError struct {
	Code        string
	Description string
}

func (e *RegistrationError) Error() string { return e.Description }

func newRegistrationError(code, description string) error {
	return &RegistrationError{Code: code, Description: description}
}

// RegisterPublicClient 按 RFC 7591 登记一个 public client（无 secret）。
// 动态注册出来的 client 一律是 public：调用方是用户机器上的原生程序，
// 任何下发出去的 secret 都等同于公开值，安全性只能由 PKCE 提供。
func (s *OAuth2ClientService) RegisterPublicClient(ctx context.Context, params *dto.OAuth2ClientRegistrationRequest) (*dto.OAuth2ClientRegistrationResponse, error) {
	if params == nil {
		return nil, newRegistrationError(RegistrationErrInvalidClientMetadata, "request body is required")
	}
	if method := strings.TrimSpace(params.TokenEndpointAuthMethod); method != "" && method != "none" {
		return nil, newRegistrationError(RegistrationErrInvalidClientMetadata,
			"only token_endpoint_auth_method=none is supported; confidential clients must be created by an administrator")
	}

	redirectURIs, err := normalizeRegistrationRedirectURIs(params.RedirectURIs)
	if err != nil {
		return nil, err
	}
	grantTypes, err := normalizeRegistrationGrantTypes(params.GrantTypes)
	if err != nil {
		return nil, err
	}
	if err := validateRegistrationResponseTypes(params.ResponseTypes); err != nil {
		return nil, err
	}
	scope, err := normalizeRegistrationScope(params.Scope)
	if err != nil {
		return nil, err
	}

	redirectJSON, err := json.Marshal(redirectURIs)
	if err != nil {
		return nil, err
	}
	scopeJSON, err := json.Marshal(strings.Fields(scope))
	if err != nil {
		return nil, err
	}
	grantJSON, err := json.Marshal(grantTypes)
	if err != nil {
		return nil, err
	}

	clientID := gowk.GenerateRandomString(32)
	created, err := s.getQueries(ctx).CreateOAuth2Client(ctx, db2.CreateOAuth2ClientParams{
		ID:              clientID,
		Name:            registrationClientName(params.ClientName),
		Secret:          "",
		RedirectUris:    string(redirectJSON),
		Scopes:          string(scopeJSON),
		GrantTypes:      string(grantJSON),
		AccessTokenTtl:  3600,
		RefreshTokenTtl: 2592000,
		Created:         pgtype.Timestamptz{Time: time.Now(), Valid: true},
		Updated:         pgtype.Timestamptz{Time: time.Now(), Valid: true},
		Enabled:         true,
	})
	if err != nil {
		return nil, err
	}

	return &dto.OAuth2ClientRegistrationResponse{
		ClientID:                created.ID,
		ClientIDIssuedAt:        created.Created.Time.Unix(),
		ClientName:              created.Name,
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           []string{"code"},
		Scope:                   scope,
		TokenEndpointAuthMethod: "none",
	}, nil
}

// normalizeRegistrationRedirectURIs 去重并逐个校验回调地址。
func normalizeRegistrationRedirectURIs(raw []string) ([]string, error) {
	if len(raw) == 0 || len(raw) > 10 {
		return nil, newRegistrationError(RegistrationErrInvalidRedirectURI, "redirect_uris must contain between 1 and 10 entries")
	}
	seen := make(map[string]struct{}, len(raw))
	result := make([]string, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if err := validateRegistrationRedirectURI(entry); err != nil {
			return nil, err
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		result = append(result, entry)
	}
	return result, nil
}

// validateRegistrationRedirectURI 只放行 https 与回环 http。
//
// 原生客户端的回调必须是回环地址（RFC 8252 §7.3），端口每次启动都可能不同，
// 因此不限制端口；明文 http 只对回环豁免，其余一律要求 https。
func validateRegistrationRedirectURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
		return newRegistrationError(RegistrationErrInvalidRedirectURI, "redirect_uri is malformed: "+raw)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return newRegistrationError(RegistrationErrInvalidRedirectURI,
		"redirect_uri must use https, or http on a loopback host: "+raw)
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

func normalizeRegistrationGrantTypes(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return registrationGrantTypes, nil
	}
	allowed := make(map[string]struct{}, len(registrationGrantTypes))
	for _, g := range registrationGrantTypes {
		allowed[g] = struct{}{}
	}
	hasAuthCode := false
	result := make([]string, 0, len(raw))
	for _, g := range raw {
		g = strings.TrimSpace(g)
		if _, ok := allowed[g]; !ok {
			return nil, newRegistrationError(RegistrationErrInvalidClientMetadata, "unsupported grant_type: "+g)
		}
		if g == "authorization_code" {
			hasAuthCode = true
		}
		result = append(result, g)
	}
	if !hasAuthCode {
		return nil, newRegistrationError(RegistrationErrInvalidClientMetadata, "grant_types must include authorization_code")
	}
	return result, nil
}

func validateRegistrationResponseTypes(raw []string) error {
	for _, rt := range raw {
		if strings.TrimSpace(rt) != "code" {
			return newRegistrationError(RegistrationErrInvalidClientMetadata, "unsupported response_type: "+rt)
		}
	}
	return nil
}

func normalizeRegistrationScope(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultAuthorizeScope, nil
	}
	allowed := make(map[string]struct{}, len(registrationScopes))
	for _, s := range registrationScopes {
		allowed[s] = struct{}{}
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, 4)
	for _, s := range strings.Fields(raw) {
		if _, ok := allowed[s]; !ok {
			return "", newRegistrationError(RegistrationErrInvalidClientMetadata, "scope not allowed: "+s)
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		result = append(result, s)
	}
	return strings.Join(result, " "), nil
}

// registrationClientName 取客户端自报名字，空则给占位名；
// 名字只用于授权确认页展示，长度上限与后台创建的 client 保持一致。
func registrationClientName(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "MCP 客户端"
	}
	if utf8.RuneCountInString(name) > 100 {
		name = string([]rune(name)[:100])
	}
	return name
}
