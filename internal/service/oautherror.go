package service

import "net/http"

// RFC 6749 §5.2 / RFC 7009 / RFC 7662 定义的 error 取值。
// 协议端点直接把这些值原样写给客户端，第三方库靠它分支处理。
const (
	OAuthErrInvalidRequest       = "invalid_request"
	OAuthErrInvalidClient        = "invalid_client"
	OAuthErrInvalidGrant         = "invalid_grant"
	OAuthErrUnauthorizedClient   = "unauthorized_client"
	OAuthErrUnsupportedGrantType = "unsupported_grant_type"
	OAuthErrInvalidScope         = "invalid_scope"
	OAuthErrServerError          = "server_error"
	OAuthErrUnavailable          = "temporarily_unavailable"
)

// OAuthError 表示 OAuth2 协议层错误，携带标准 error 标识与配套 HTTP 状态码。
// 与平台内部业务错误（gowk.ErrorCode）区分开：只有协议端点会把 OAuthError
// 直接写进响应体，其余接口仍走平台统一包装。
type OAuthError struct {
	Code        string
	Description string
	Status      int
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func newOAuthError(code, description string, status int) *OAuthError {
	return &OAuthError{Code: code, Description: description, Status: status}
}

// invalidClient 表示客户端认证失败。按 RFC 6749 §5.2 必须回 401，
// 且状态码与 invalid_grant（400）不同——客户端凭此判断是"凭据错了"
// 还是"授权码/令牌错了"。
func invalidClient(description string) *OAuthError {
	return newOAuthError(OAuthErrInvalidClient, description, http.StatusUnauthorized)
}

func invalidGrant(description string) *OAuthError {
	return newOAuthError(OAuthErrInvalidGrant, description, http.StatusBadRequest)
}

func invalidScope(description string) *OAuthError {
	return newOAuthError(OAuthErrInvalidScope, description, http.StatusBadRequest)
}

func invalidRequest(description string) *OAuthError {
	return newOAuthError(OAuthErrInvalidRequest, description, http.StatusBadRequest)
}
