// Package dto 是 auth 的纯数据传输对象集合，不依赖 internal/db 等服务端代码，
// 因此可被第三方直接 import。
// db 实体到 DTO 的转换（依赖 internal/db）放在服务端 internal/service。
package dto

// Login parameters
type LoginParams struct {
	Account string `json:"account" binding:"required"`    // Phone or Email
	Code    string `json:"code" binding:"required,len=6"` // OTP code
}

// Login response
type LoginRes struct {
	Token      string `json:"token"`
	UserId     int64  `json:"userId"`
	Nickname   string `json:"nickname"`
	Avatar     string `json:"avatar,omitempty"`
	IsVerified bool   `json:"isVerified"`
}

// User response (excludes sensitive data)
type UserRes struct {
	Id          int64  `json:"id"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	Nickname    string `json:"nickname"`
	Group       string `json:"group"`
	Avatar      string `json:"avatar,omitempty"`
	IsVerified  bool   `json:"isVerified"`
	Enabled     bool   `json:"enabled"`
	LastLoginAt string `json:"lastLoginAt,omitempty"`
	Created     string `json:"created"`
}

type ProfileUpdateParams struct {
	Phone    string `json:"phone" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Nickname string `json:"nickname" binding:"required"`
}

// SendVerificationCodeParams 请求下发一次性验证码。
type SendVerificationCodeParams struct {
	Target  string `json:"target" binding:"required,max=254"`
	Purpose string `json:"purpose" binding:"required,oneof=login register verify_email"`
}

// CodeLoginParams 验证码登录；邮箱不存在且放开自动注册时顺带建号。
type CodeLoginParams struct {
	Target string `json:"target" binding:"required,max=254"`
	Code   string `json:"code" binding:"required,len=6"`
}

// CodeRegisterParams 用验证码显式注册；邮箱已被占用时返回 400。
type CodeRegisterParams struct {
	Target string `json:"target" binding:"required,max=254"`
	Code   string `json:"code" binding:"required,len=6"`
}

// IdentityProviderParams 新增/编辑第三方 OIDC provider。
// Name 仅在创建时生效（创建后不可改名，因为 auth_identity.provider 存的就是它），
// ClientSecret 更新时留空表示保持原值。
type IdentityProviderParams struct {
	Name         string `json:"name" binding:"max=32"`
	Label        string `json:"label" binding:"required,min=1,max=50"`
	Issuer       string `json:"issuer" binding:"required,max=500"`
	ClientID     string `json:"client_id" binding:"required,max=255"`
	ClientSecret string `json:"client_secret,omitempty" binding:"max=500"`
	Scopes       string `json:"scopes,omitempty" binding:"max=255"`
	AutoRegister *bool  `json:"auto_register,omitempty"`
	Enabled      *bool  `json:"enabled,omitempty"`
}

// IdentityProviderRes 是第三方 provider 的管理侧视图。
// 只回 SecretSet 布尔值，任何情况下都不回显密钥。
type IdentityProviderRes struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Label        string `json:"label"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	SecretSet    bool   `json:"secret_set"`
	Scopes       string `json:"scopes"`
	AutoRegister bool   `json:"auto_register"`
	Enabled      bool   `json:"enabled"`
	CallbackURL  string `json:"callback_url"`
	Created      string `json:"created"`
	Updated      string `json:"updated"`
}

// PublicIdentityProvider 是登录页渲染按钮所需的最小信息。
type PublicIdentityProvider struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// IdentityBindingRes 是账号中心展示"已绑定的第三方账号"用的视图。
type IdentityBindingRes struct {
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	Avatar      string `json:"avatar,omitempty"`
	Created     string `json:"created"`
}

// OAuth2 DTOs
type OAuth2AuthRequest struct {
	ResponseType string `json:"response_type" form:"response_type" binding:"required,oneof=code"`
	ClientID     string `json:"client_id" form:"client_id" binding:"required,min=1,max=100"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" binding:"required,url"`
	// Scope 允许留空：部分 MCP 客户端不带 scope 直接发起授权，
	// 空值由调用方补默认集合，而不是按参数错误拒绝。
	Scope string `json:"scope" form:"scope" binding:"omitempty,max=500"`
	State string `json:"state" form:"state" binding:"omitempty,max=100"`
	Nonce string `json:"nonce" form:"nonce" binding:"omitempty,max=100"`
	// PKCE (RFC 7636)：public client 应当强制传入；S256 推荐，plain 仅作兼容。
	CodeChallenge       string `json:"code_challenge,omitempty" form:"code_challenge" binding:"omitempty,min=43,max=128"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty" form:"code_challenge_method" binding:"omitempty,oneof=S256 plain"`
}

type OAuth2TokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type" binding:"required,oneof=authorization_code client_credentials refresh_token"`
	Code         string `json:"code" form:"code" binding:"omitempty,min=10,max=100"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" binding:"omitempty,url"`
	ClientID     string `json:"client_id" form:"client_id" binding:"omitempty,min=1,max=100"`
	ClientSecret string `json:"client_secret" form:"client_secret" binding:"omitempty,min=16,max=128"`
	RefreshToken string `json:"refresh_token" form:"refresh_token" binding:"omitempty,min=10,max=500"`
	Scope        string `json:"scope" form:"scope" binding:"omitempty,min=1,max=500"`
	// OIDC specific fields
	CodeVerifier string `json:"code_verifier" form:"code_verifier" binding:"omitempty,min=43,max=128"` // PKCE
}

type OAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	// OIDC specific fields
	IDToken string `json:"id_token,omitempty"` // OpenID Connect ID Token
}

type OAuth2ClientResponse struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Secret          string `json:"secret,omitempty"`
	RedirectURIs    string `json:"redirect_uris"`
	Scopes          string `json:"scopes"`
	GrantTypes      string `json:"grant_types"`
	AccessTokenTTL  int64  `json:"access_token_ttl"`
	RefreshTokenTTL int64  `json:"refresh_token_ttl"`
	Created         string `json:"created"`
	Updated         string `json:"updated"`
	Enabled         bool   `json:"enabled"` // true = active, false = disabled
}

// OAuth Client Management DTOs
type OAuth2ClientCreateParams struct {
	// ID 留空时由服务端生成随机值；非空时按调用方指定的值登记，便于接入方配置易读的 client_id。
	ID              string   `json:"id" binding:"omitempty,max=64"`
	Name            string   `json:"name" binding:"required,min=2,max=100"`
	RedirectURIs    []string `json:"redirect_uris" binding:"required,min=1"`
	Scopes          []string `json:"scopes" binding:"required,min=1"`
	GrantTypes      []string `json:"grant_types" binding:"required,min=1"`
	AccessTokenTTL  int64    `json:"access_token_ttl" binding:"omitempty,min=300"`   // 留空或 0 用服务端默认 1 小时
	RefreshTokenTTL int64    `json:"refresh_token_ttl" binding:"omitempty,min=3600"` // 留空或 0 用服务端默认 30 天
}

type OAuth2ClientUpdateParams struct {
	ID           string   `json:"id" binding:"required"`
	Name         string   `json:"name,omitempty" binding:"omitempty,min=2,max=100"`
	Secret       string   `json:"secret,omitempty" binding:"omitempty,min=16,max=128"`
	RedirectURIs []string `json:"redirect_uris,omitempty" binding:"omitempty,min=1"`
	Scopes       []string `json:"scopes,omitempty" binding:"omitempty,min=1"`
	// 用指针以区分"未传入"与"显式 false"——未传入时保持库内值不变。
	Enabled         *bool    `json:"enabled,omitempty"`
	GrantTypes      []string `json:"grant_types,omitempty" binding:"omitempty,min=1"`
	AccessTokenTTL  int64    `json:"access_token_ttl,omitempty" binding:"omitempty,min=300"`
	RefreshTokenTTL int64    `json:"refresh_token_ttl,omitempty" binding:"omitempty,min=3600"`
}

// OAuth2ClientRegistrationRequest 是 RFC 7591 动态客户端注册请求体。
// 只接受 public client：MCP 客户端是装在用户机器上的原生程序，无法保管 secret，
// 鉴权完全依赖 PKCE。
type OAuth2ClientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	SoftwareID              string   `json:"software_id,omitempty"`
}

// OAuth2ClientRegistrationResponse 为注册结果的回显，字段名遵循 RFC 7591 §3.2.1。
// 不签发 registration_access_token，因此也没有 registration_client_uri：
// 客户端需要变更登记信息时重新注册即可。
type OAuth2ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// OpenID Connect (OIDC) DTOs
type OIDCDiscoveryResponse struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksUri                          string   `json:"jwks_uri"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// TokenEndpointAuthMethodsSupported 告知客户端可用的客户端认证方式：
	// client_secret_basic 与 client_secret_post。缺省时标准客户端会按规范默认
	// 只用 client_secret_basic，导致仅配置 form 凭据的接入失败。
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// CodeChallengeMethodsSupported 告知支持的 PKCE 变换方法。
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	// ClaimsSupported 声明 userinfo / id_token 可返回的 claims。
	ClaimsSupported []string `json:"claims_supported"`
	// EndSessionEndpoint 供 RP 发起登出（OIDC RP-Initiated Logout）。
	EndSessionEndpoint string `json:"end_session_endpoint"`
	// RevocationEndpoint 对应 RFC 7009 的 token 撤销端点。
	RevocationEndpoint string `json:"revocation_endpoint"`
	// IntrospectionEndpoint 对应 RFC 7662 的 token 内省端点。
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	// RegistrationEndpoint 对应 RFC 7591 的动态客户端注册端点：
	// MCP 客户端据此自助登记，不必人工在后台建 client。
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	// RevocationEndpointAuthMethodsSupported / IntrospectionEndpointAuthMethodsSupported
	// 与 token 端点一致：Basic 与 form 两种客户端认证方式都接受。
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
}

// OAuth2RevokeRequest 是 RFC 7009 的撤销请求参数。
type OAuth2RevokeRequest struct {
	Token         string `form:"token" json:"token" binding:"required,min=10,max=500"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint" binding:"omitempty,oneof=access_token refresh_token"`
	ClientID      string `form:"client_id" json:"client_id" binding:"omitempty,min=1,max=100"`
	ClientSecret  string `form:"client_secret" json:"client_secret" binding:"omitempty,min=16,max=128"`
}

// OAuth2IntrospectRequest 是 RFC 7662 的内省请求参数。
type OAuth2IntrospectRequest struct {
	Token         string `form:"token" json:"token" binding:"required,min=10,max=500"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint" binding:"omitempty,oneof=access_token refresh_token"`
	ClientID      string `form:"client_id" json:"client_id" binding:"omitempty,min=1,max=100"`
	ClientSecret  string `form:"client_secret" json:"client_secret" binding:"omitempty,min=16,max=128"`
}

// OIDCIntrospectResponse 是 RFC 7662 §2.2 定义的响应体。
// 非活跃 token 只回 {"active": false}，其余字段全部省略。
type OIDCIntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
}

type OIDCAddress struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

type OIDCUserInfo struct {
	Sub               string       `json:"sub"`
	Name              string       `json:"name,omitempty"`
	GivenName         string       `json:"given_name,omitempty"`
	FamilyName        string       `json:"family_name,omitempty"`
	MiddleName        string       `json:"middle_name,omitempty"`
	Nickname          string       `json:"nickname,omitempty"`
	PreferredUsername string       `json:"preferred_username"`
	Profile           string       `json:"profile,omitempty"`
	Picture           string       `json:"picture,omitempty"`
	Website           string       `json:"website,omitempty"`
	Email             string       `json:"email,omitempty"`
	EmailVerified     bool         `json:"email_verified,omitempty"`
	Gender            string       `json:"gender,omitempty"`
	Birthdate         string       `json:"birthdate,omitempty"`
	ZoneInfo          string       `json:"zoneinfo,omitempty"`
	Locale            string       `json:"locale,omitempty"`
	PhoneNumber       string       `json:"phone_number,omitempty"`
	PhoneVerified     bool         `json:"phone_number_verified,omitempty"`
	Address           *OIDCAddress `json:"address,omitempty"`
	UpdatedAt         int64        `json:"updated_at,omitempty"`
}

type OIDCJwksResponse struct {
	Keys []OIDCJwk `json:"keys"`
}

type OIDCJwk struct {
	Kty string `json:"kty"` // Key Type (e.g., "RSA")
	Use string `json:"use"` // Public Key Use (e.g., "sig")
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // Modulus for RSA keys
	E   string `json:"e"`   // Exponent for RSA keys
	Alg string `json:"alg"` // Algorithm (e.g., "RS256")
}
