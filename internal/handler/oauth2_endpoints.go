package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

// OAuth2Revoke 实现 RFC 7009 的 token 撤销端点。
// 按规范，撤销成功与"token 根本不存在"都返回 200，调用方无从区分。
func (o *OAuth2Handler) OAuth2Revoke(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")

	var params dto.OAuth2RevokeRequest
	if err := ctx.ShouldBind(&params); err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if clientID, clientSecret, ok := parseBasicAuth(ctx.GetHeader("Authorization")); ok {
		params.ClientID = clientID
		params.ClientSecret = clientSecret
	}

	if err := o.oauth2Service.RevokeToken(ctx, params.ClientID, params.ClientSecret, params.Token, params.TokenTypeHint); err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}
	ctx.Status(http.StatusOK)
	ctx.Abort()
}

// OAuth2Introspect 实现 RFC 7662 的 token 内省端点，供资源服务器判断 token 是否仍然活跃。
func (o *OAuth2Handler) OAuth2Introspect(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")

	var params dto.OAuth2IntrospectRequest
	if err := ctx.ShouldBind(&params); err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if clientID, clientSecret, ok := parseBasicAuth(ctx.GetHeader("Authorization")); ok {
		params.ClientID = clientID
		params.ClientSecret = clientSecret
	}

	response, err := o.oauth2Service.IntrospectToken(ctx, params.ClientID, params.ClientSecret, params.Token, params.TokenTypeHint)
	if err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}
	ctx.JSON(http.StatusOK, response)
	ctx.Abort()
}

// OIDCEndSession 实现 RP 发起的登出：清掉浏览器会话，并按需跳回登记过的地址。
//
// post_logout_redirect_uri 必须命中某个启用 client 的登记地址，否则这个端点
// 会变成对任意域名的开放重定向。
func (o *OAuth2Handler) OIDCEndSession(ctx *gin.Context) {
	postLogoutURI := strings.TrimSpace(ctx.Query("post_logout_redirect_uri"))
	state := ctx.Query("state")

	// 吊销服务端会话：仅 Redis token store 下才能真正删除，与 /logout 行为一致。
	if token, err := ctx.Cookie("oidc_jwt"); err == nil && token != "" && gowk.HasRedis() {
		if client := gowk.Redis(); client != nil {
			_ = client.Del(ctx.Request.Context(), gowkRedisTokenPrefix+token).Err()
		}
	}
	ctx.SetCookie("oidc_jwt", "", -1, "/", "", gowk.CookieSecure(), true)

	if postLogoutURI == "" {
		ctx.String(http.StatusOK, "已退出登录")
		ctx.Abort()
		return
	}

	if !o.oauth2Service.IsRegisteredRedirectURI(ctx, postLogoutURI) {
		writeOAuthError(ctx, errors.New("post_logout_redirect_uri is not registered by any client"),
			service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}

	u, err := url.Parse(postLogoutURI)
	if err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if state != "" {
		query := u.Query()
		query.Set("state", state)
		u.RawQuery = query.Encode()
	}
	ctx.Redirect(http.StatusFound, u.String())
	ctx.Abort()
}
