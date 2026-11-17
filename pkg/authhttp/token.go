package authhttp

import (
	"context"
	"errors"
	"time"

	"github.com/iautre/auth/internal/service"
)

var (
	// ErrAccessTokenInvalid 表示 token 不存在、已过期，或签发它的 client 已被禁用。
	ErrAccessTokenInvalid = errors.New("auth: access token is invalid or expired")
	// ErrAccessTokenAudience 表示 token 是给别的资源签发的。
	ErrAccessTokenAudience = errors.New("auth: access token was issued for a different resource")
)

// AccessTokenInfo 是 access token 的公开视图。
// 刻意不暴露 internal/db 的行结构：那属于 Auth 的私有表结构，改动不该传导给宿主。
type AccessTokenInfo struct {
	UserID int64
	// ClientID 是签发这张 token 的 OAuth2 client。
	ClientID string
	Scope    string
	// Audience 是 RFC 8707 的资源指示；为空表示签发时没有声明资源。
	Audience string
	Expires  time.Time
}

// ValidateAccessToken 在进程内校验 Auth 签发的 access token，不发起 HTTP 请求。
// 调用前提：宿主已通过 gowk 初始化 PostgreSQL（走 Setup 或 gowk.Run 都会初始化）。
func ValidateAccessToken(ctx context.Context, accessToken string) (*AccessTokenInfo, error) {
	return ValidateAccessTokenFor(ctx, accessToken, "")
}

// ValidateAccessTokenFor 额外要求 token 的 audience 与期望资源一致。
//
// audience 传空表示不做资源绑定校验；token 本身没有 audience（客户端没声明
// resource）时也放行，否则所有不支持 RFC 8707 的客户端会被一并拒绝。
func ValidateAccessTokenFor(ctx context.Context, accessToken, audience string) (*AccessTokenInfo, error) {
	if accessToken == "" {
		return nil, ErrAccessTokenInvalid
	}

	var oauth2Service service.OAuth2Service
	token, err := oauth2Service.ValidateAccessTokenFor(ctx, accessToken, audience)
	if err != nil {
		if errors.Is(err, service.ErrAudienceMismatch) {
			return nil, ErrAccessTokenAudience
		}
		return nil, ErrAccessTokenInvalid
	}

	return &AccessTokenInfo{
		UserID:   token.UserID,
		ClientID: token.ClientID,
		Scope:    token.Scope.String,
		Audience: token.Audience.String,
		Expires:  token.Expires.Time,
	}, nil
}
