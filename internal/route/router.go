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
	o := handler.NewOAuth2Handler(ctx, ro.BasePath())
	oc := handler.NewOAuth2ClientHandler(ctx)
	p := handler.NewPasskeyHandler()
	otp := handler.NewOTPHandler()

	// User endpoints
	// 注意：/login 由调用方（cmd 独立部署 或 embed.Setup）统一注册，
	// 避免与 embed.Setup 外层注册冲突导致 gin 重复注册 panic。
	ro.GET("/user/info", gowk.CheckLogin, u.UserInfo)
	ro.PUT("/user/profile", gowk.CheckLogin, handler.BrowserSameOrigin, u.UpdateProfile)
	ro.POST("/logout", gowk.CheckLogin, handler.BrowserSameOrigin, u.Logout)
	ro.GET("/otp/credentials", gowk.CheckLogin, otp.Credentials)
	ro.POST("/otp/enrollment/begin", gowk.CheckLogin, handler.BrowserSameOrigin, otp.EnrollmentBegin)
	ro.POST("/otp/enrollment/finish", gowk.CheckLogin, handler.BrowserSameOrigin, otp.EnrollmentFinish)
	ro.DELETE("/otp/credentials/:id", gowk.CheckLogin, handler.BrowserSameOrigin, otp.DeleteCredential)
	ro.GET("/passkey/status", gowk.CheckLogin, p.Status)
	ro.GET("/passkey/credentials", gowk.CheckLogin, p.Credentials)
	ro.PATCH("/passkey/credentials/:id", gowk.CheckLogin, handler.BrowserSameOrigin, p.UpdateCredentialName)
	ro.DELETE("/passkey/credentials/:id", gowk.CheckLogin, handler.BrowserSameOrigin, p.DeleteCredential)
	ro.POST("/passkey/register/begin", gowk.CheckLogin, handler.BrowserSameOrigin, p.RegisterBegin)
	ro.POST("/passkey/register/finish", gowk.CheckLogin, handler.BrowserSameOrigin, p.RegisterFinish)
	ro.POST("/passkey/login/begin", p.LoginBegin)
	ro.POST("/passkey/login/finish", p.LoginFinish)
	// /sso/login 当前 service 层直接返回 ErrSSONotImplemented，没有任何 provider 接入，
	// 路由暴露反而误导上游。等真正落地某个第三方 IDP 时再注册回来。

	// Admin endpoints (require admin middleware)
	ro.POST("/user/:userId/reset-otp", gowk.CheckLogin, handler.AdminMiddleware, u.ResetOTPCode)

	// OAuth2 endpoints
	ro.GET("/oauth2/auth", handler.OAuth2BrowserLogin(ro.BasePath()), o.OAuth2Auth)
	ro.POST("/oauth2/token", o.OAuth2Token)

	// OIDC endpoints
	ro.GET("/.well-known/openid-configuration", o.OIDCDiscovery)
	ro.POST("/oidc/token", o.OIDCToken)
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
