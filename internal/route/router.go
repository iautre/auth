package route

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/gowk"
)

func routeGroup(r *gin.RouterGroup, relativePath ...string) *gin.RouterGroup {
	var ro *gin.RouterGroup
	if len(relativePath) > 0 {
		ro = r.Group(relativePath[0])
	} else {
		ro = r
	}

	return ro
}

// API registers Auth's application-facing HTTP API. It intentionally excludes
// OAuth/OIDC protocol endpoints and browser pages so host applications do not
// accidentally expose an authorization server below their business API prefix.
func API(r *gin.RouterGroup, relativePath ...string) *gin.RouterGroup {
	ro := routeGroup(r, relativePath...)

	// Create handlers with context
	ctx := context.Background()
	u := handler.NewUserHandler(ctx)
	p := handler.NewPasskeyHandler()
	otp := handler.NewOTPHandler()
	auth := handler.NewAuthHandler()
	identity := handler.NewIdentityHandler()
	provider := handler.NewIdentityProviderHandler()

	// 无密码登录：一次性验证码（注册即登录）、显式验证码注册
	ro.POST("/register/code", auth.RegisterWithCode)
	ro.POST("/login/code", auth.LoginWithCode)
	ro.POST("/verification/send", auth.SendCode)

	// 当前用户已绑定的第三方身份
	ro.GET("/identities", gowk.CheckLogin, identity.List)
	ro.DELETE("/identities/:provider", gowk.CheckLogin, handler.BrowserSameOrigin, identity.Unlink)

	// 第三方登录方式管理（管理员）
	ro.GET("/admin/identity-providers", gowk.CheckLogin, handler.AdminMiddleware, provider.List)
	ro.POST("/admin/identity-providers", gowk.CheckLogin, handler.AdminMiddleware, provider.Create)
	ro.PUT("/admin/identity-providers/:id", gowk.CheckLogin, handler.AdminMiddleware, provider.Update)
	ro.DELETE("/admin/identity-providers/:id", gowk.CheckLogin, handler.AdminMiddleware, provider.Delete)

	// User endpoints
	// 注意：POST /login 由 authhttp.MountAPI 注册；Auth 内置的
	// GET 登录页面仅由 cmd 独立部署入口注册。
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

	// Admin endpoints (require admin middleware)
	ro.POST("/user/:userId/reset-otp", gowk.CheckLogin, handler.AdminMiddleware, u.ResetOTPCode)

	return ro
}

// OAuth registers the OAuth2/OIDC authorization-server protocol surface.
// loginURL belongs to the application that owns the browser UI. When it is
// empty, anonymous authorization requests receive the handler's standard 401.
// mcpPath 非空时同时暴露该 MCP 资源的 RFC 9728 元数据，供第三方客户端发现。
func OAuth(r *gin.RouterGroup, loginURL string, mcpPath string) *gin.RouterGroup {
	ro := r
	ctx := context.Background()
	o := handler.NewOAuth2Handler(ctx)
	oc := handler.NewOAuth2ClientHandler(ctx)

	// OAuth2 endpoints
	login := handler.OAuth2BrowserLogin(loginURL)
	ro.GET("/oauth2/authorize", login, o.OAuth2Auth)
	ro.POST("/oauth2/authorize", login, o.OAuth2AuthDecision)
	ro.POST("/oauth2/token", o.OIDCToken)
	// RFC 7591 动态客户端注册：MCP 客户端自助登记，不必人工建 client。
	ro.POST("/oauth2/register", o.OAuth2Register)
	// RFC 7009 撤销、RFC 7662 内省：供接入方主动失效与校验 token。
	ro.POST("/oauth2/revoke", o.OAuth2Revoke)
	ro.POST("/oauth2/introspect", o.OAuth2Introspect)
	// OIDC RP-Initiated Logout：清浏览器会话并跳回登记过的地址。
	ro.GET("/oauth2/end_session", o.OIDCEndSession)

	// OIDC endpoints
	ro.GET("/.well-known/openid-configuration", o.OIDCDiscovery)
	ro.GET("/oidc/userinfo", handler.OAuth2TokenMiddleware, o.OIDCUserInfo)
	ro.GET("/oidc/jwks", o.OIDCJwks)

	// RFC 9728 保护资源元数据：客户端在 /mcp 收到 401 后按这里的地址来找授权服务器。
	// 根路径那份描述"整个服务"，带路径那份精确描述 MCP 资源，两者都给出。
	if mcpPath != "" {
		ro.GET("/.well-known/oauth-protected-resource", handler.ProtectedResourceMetadata(""))
		ro.GET(handler.ProtectedResourceMetadataPath(mcpPath), handler.ProtectedResourceMetadata(mcpPath))
	}

	// OAuth2 Client Management endpoints (admin only)
	// 鉴权用平台登录态而非 OAuth2 access token：access token 必须先存在 client
	// 才能签发，若这里也要求 access token，全新部署将永远无法创建第一个 client。
	ro.POST("/oauth2/clients", gowk.CheckLogin, handler.AdminMiddleware, oc.CreateOAuth2Client)
	ro.GET("/oauth2/clients", gowk.CheckLogin, handler.AdminMiddleware, oc.ListOAuth2Clients)
	ro.GET("/oauth2/clients/:id", gowk.CheckLogin, handler.AdminMiddleware, oc.GetOAuth2Client)
	ro.PUT("/oauth2/clients/:id", gowk.CheckLogin, handler.AdminMiddleware, oc.UpdateOAuth2Client)
	ro.DELETE("/oauth2/clients/:id/disable", gowk.CheckLogin, handler.AdminMiddleware, oc.DisableOAuth2Client)
	ro.POST("/oauth2/clients/:id/regenerate-secret", gowk.CheckLogin, handler.AdminMiddleware, oc.RegenerateClientSecret)

	return ro
}

// Federated registers third-party OIDC login endpoints: auth acts as the
// relying party and lets users sign in with an external provider.
// Paths are fixed at the root because callback URLs must be registered with
// each provider and cannot move with the host application's API prefix.
func Federated(r *gin.RouterGroup, loginURL string) *gin.RouterGroup {
	ro := r
	f := handler.NewFederatedHandler(loginURL)

	// 公开：登录页渲染按钮用
	ro.GET("/federated/providers", f.Providers)
	ro.GET("/federated/:provider/login", f.BeginLogin)
	ro.GET("/federated/:provider/callback", f.Callback)

	return ro
}
