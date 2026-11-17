package service

import (
	"context"
	"encoding/json"
	"fmt"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/dto"
)

// RevokeToken 按 RFC 7009 撤销 access token 或 refresh token。
//
// 两条约束：
//   - 客户端必须自行通过认证，未经认证的撤销请求一律拒绝；
//   - 只能撤销自己签发的 token。不属于该 client 的 token 按"不存在"处理，
//     否则撤销接口会变成一个探测别人 token 是否有效的oracle。
//
// RFC 7009 §2.2 要求：无论 token 是否存在都应返回成功，调用方无从判断
// 目标是否存在——因此这里对"查不到"也返回 nil。
func (o *OAuth2Service) RevokeToken(ctx context.Context, clientID, clientSecret, token, hint string) error {
	if _, err := o.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return err
	}

	if hint == "refresh_token" {
		if revoked, err := o.revokeRefreshTokenIfOwned(ctx, token, clientID); err != nil || revoked {
			return err
		}
	}

	if revoked, err := o.revokeAccessTokenIfOwned(ctx, token, clientID); err != nil || revoked {
		return err
	}

	if hint != "refresh_token" {
		if _, err := o.revokeRefreshTokenIfOwned(ctx, token, clientID); err != nil {
			return err
		}
	}
	return nil
}

func (o *OAuth2Service) revokeAccessTokenIfOwned(ctx context.Context, token, clientID string) (bool, error) {
	queries := o.getQueries(ctx)
	accessToken, err := queries.GetOAuth2Token(ctx, token)
	if err != nil || accessToken.ClientID != clientID {
		return false, nil
	}
	if err := queries.RevokeOAuth2Token(ctx, token); err != nil {
		return false, fmt.Errorf("revoke access token: %w", err)
	}
	revokeAccessTokenCache(ctx, token)
	return true, nil
}

func (o *OAuth2Service) revokeRefreshTokenIfOwned(ctx context.Context, token, clientID string) (bool, error) {
	queries := o.getQueries(ctx)
	refreshToken, err := queries.GetOAuth2RefreshToken(ctx, token)
	if err != nil || refreshToken.ClientID != clientID {
		return false, nil
	}
	if err := queries.RevokeOAuth2RefreshToken(ctx, token); err != nil {
		return false, fmt.Errorf("revoke refresh token: %w", err)
	}
	return true, nil
}

// IntrospectToken 按 RFC 7662 返回 token 的活跃状态与元数据。
// 非本 client 签发的 token、以及已过期的 token 一律回 active=false，
// 不区分"不存在"与"无权查看"。
func (o *OAuth2Service) IntrospectToken(ctx context.Context, clientID, clientSecret, token, hint string) (*dto.OIDCIntrospectResponse, error) {
	if _, err := o.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	queries := o.getQueries(ctx)
	inactive := &dto.OIDCIntrospectResponse{Active: false}

	if hint != "refresh_token" {
		if accessToken, err := queries.GetOAuth2Token(ctx, token); err == nil {
			if accessToken.ClientID != clientID {
				return inactive, nil
			}
			return buildIntrospectResponse(accessToken, "Bearer"), nil
		}
	}
	if refreshToken, err := queries.GetOAuth2RefreshToken(ctx, token); err == nil {
		if refreshToken.ClientID != clientID {
			return inactive, nil
		}
		return buildRefreshIntrospectResponse(refreshToken), nil
	}
	return inactive, nil
}

func buildIntrospectResponse(token db2.AuthOauth2Token, tokenType string) *dto.OIDCIntrospectResponse {
	response := &dto.OIDCIntrospectResponse{
		Active:    true,
		Scope:     token.Scope.String,
		ClientID:  token.ClientID,
		TokenType: tokenType,
		Exp:       token.Expires.Time.Unix(),
		Iat:       token.Created.Time.Unix(),
	}
	if token.UserID > 0 {
		response.Sub = fmt.Sprintf("%d", token.UserID)
	}
	return response
}

func buildRefreshIntrospectResponse(token db2.AuthOauth2RefreshToken) *dto.OIDCIntrospectResponse {
	response := &dto.OIDCIntrospectResponse{
		Active:    true,
		Scope:     token.Scope.String,
		ClientID:  token.ClientID,
		TokenType: "refresh_token",
		Exp:       token.Expires.Time.Unix(),
		Iat:       token.Created.Time.Unix(),
	}
	if token.UserID > 0 {
		response.Sub = fmt.Sprintf("%d", token.UserID)
	}
	return response
}

// IsRegisteredRedirectURI 判断给定地址是否为某个启用 client 登记过的重定向地址。
// 用于 RP 发起登出时的 post_logout_redirect_uri 校验：没有这个校验，
// end_session 就成了任意地址跳转的开放重定向。
func (o *OAuth2Service) IsRegisteredRedirectURI(ctx context.Context, uri string) bool {
	clients, err := o.getQueries(ctx).ListOAuth2Client(ctx)
	if err != nil {
		return false
	}
	for _, client := range clients {
		if !client.Enabled {
			continue
		}
		var registered []string
		if err := json.Unmarshal([]byte(client.RedirectUris), &registered); err != nil {
			continue
		}
		for _, candidate := range registered {
			if candidate == uri {
				return true
			}
		}
	}
	return false
}
