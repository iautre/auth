package route

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/gowk"
)

func Router(r *gin.RouterGroup, relativePath ...string) *gin.RouterGroup {
	var ro *gin.RouterGroup
	if len(relativePath) > 0 {
		ro = r.Group(relativePath[0])
	} else {
		ro = r
	}

	// Create handlers with context
	ctx := context.Background()
	u := handler.NewUserHandler(ctx)
	o := handler.NewOAuth2Handler(ctx)
	oc := handler.NewOAuth2ClientHandler(ctx)

	// User endpoints
	// 注意：/login 由调用方（cmd 独立部署 或 embed.Setup）统一注册，
	// 避免与 embed.Setup 外层注册冲突导致 gin 重复注册 panic。
	ro.GET("/user/info", gowk.CheckLogin, u.UserInfo)
	// /sso/login 当前 service 层直接返回 ErrSSONotImplemented，没有任何 provider 接入，
	// 路由暴露反而误导上游。等真正落地某个第三方 IDP 时再注册回来。

	// Admin endpoints (require admin middleware)
	ro.POST("/user/:userId/reset-otp", gowk.CheckLogin, handler.AdminMiddleware, u.ResetOTPCode)

	// OAuth2 endpoints
	// /oauth2/auth 仅依赖 gowk.CheckLogin 鉴权；BasicAuthMiddleware 在 auth 项目中
	// 没有注册任何 SetBasicAuthValidator，validateBasicAuth 在缺凭据时直接 nil 放行，
	// 一旦上面的 CheckLogin 也按 cookie/bearer/basic 不严格执行，就会出现"无主码"。
	// 风险通过 OAuth2Auth handler 中 LoginId<=0 拦截兜底，这里不再叠 BasicAuth 中间件。
	ro.GET("/oauth2/auth", gowk.CheckLogin, o.OAuth2Auth)
	ro.POST("/oauth2/token", o.OAuth2Token)

	// OIDC endpoints
	ro.GET("/.well-known/openid_configuration", o.OIDCDiscovery)
	ro.GET("/oidc/userinfo", handler.OAuth2TokenMiddleware, o.OIDCUserInfo)
	ro.GET("/oidc/jwks", o.OIDCJwks)

	// OAuth2 Client Management endpoints (admin only)
	ro.POST("/oauth2/clients", handler.OAuth2TokenMiddleware, handler.AdminMiddleware, oc.CreateOAuth2Client)
	ro.GET("/oauth2/clients", handler.OAuth2TokenMiddleware, handler.AdminMiddleware, oc.ListOAuth2Clients)
	ro.GET("/oauth2/clients/:id", handler.OAuth2TokenMiddleware, handler.AdminMiddleware, oc.GetOAuth2Client)
	ro.PUT("/oauth2/clients/:id", handler.OAuth2TokenMiddleware, handler.AdminMiddleware, oc.UpdateOAuth2Client)
	ro.DELETE("/oauth2/clients/:id/disable", handler.OAuth2TokenMiddleware, handler.AdminMiddleware, oc.DisableOAuth2Client)
	ro.POST("/oauth2/clients/:id/regenerate-secret", handler.OAuth2TokenMiddleware, handler.AdminMiddleware, oc.RegenerateClientSecret)

	return ro
}
