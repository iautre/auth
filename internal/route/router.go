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
	ro.POST("/login", u.Login)
	ro.GET("/user/info", gowk.CheckLogin, u.UserInfo)
	ro.POST("/sso/login", u.SSOLogin)

	// Admin endpoints (require admin middleware)
	ro.POST("/user/:userId/reset-otp", gowk.CheckLogin, handler.AdminMiddleware, u.ResetOTPCode)

	// OAuth2 endpoints
	ro.GET("/oauth2/auth", gowk.CheckLogin, u.BasicAuthMiddleware, o.OAuth2Auth)
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
