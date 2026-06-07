package service

import (
	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/dto"
)

// buildOAuth2ClientResponse 把 db 实体转换为对外 DTO（默认隐藏 secret）。
//
// 该转换依赖 internal/db，刻意放在 service 包内而非 pkg/dto：
// 使 pkg/dto 保持为纯数据结构、不依赖 internal/db，从而能被 console 等远程消费方
// 通过 embed→pkg/client→pkg/dto 依赖链 go get，而不会牵连进服务端的 internal/db。
func buildOAuth2ClientResponse(client db2.AuthOauth2Client) *dto.OAuth2ClientResponse {
	return buildOAuth2ClientResponseWithSecret(client, false)
}

func buildOAuth2ClientResponseWithSecret(client db2.AuthOauth2Client, includeSecret bool) *dto.OAuth2ClientResponse {
	secret := ""
	if includeSecret {
		secret = client.Secret
	}
	return &dto.OAuth2ClientResponse{
		ID:              client.ID,
		Name:            client.Name,
		Secret:          secret,
		RedirectURIs:    client.RedirectUris,
		Scopes:          client.Scopes,
		GrantTypes:      client.GrantTypes,
		AccessTokenTTL:  client.AccessTokenTtl,
		RefreshTokenTTL: client.RefreshTokenTtl,
		Enabled:         client.Enabled,
	}
}
