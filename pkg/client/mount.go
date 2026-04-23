package client

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/gowk"
)

// MountRemote 将 auth 的 HTTP 接口以 gRPC 为后端挂载到 router 的 prefix 路由组下。
// 登录接口（POST prefix/login）由 embed.Setup 统一注册，MountRemote 只挂载其余接口：
//   GET   /user/info                — 获取完整用户信息（需 token）
//   POST  /oauth2/token             — OAuth2 token 换取
//   GET   /.well-known/openid_configuration — OIDC 发现文档
//   GET   /oidc/userinfo            — OIDC 用户信息（需 access_token）
//   GET   /oidc/jwks                — JWKS 公钥
func (c *AuthClient) MountRemote(router *gin.Engine, prefix string) {
	g := router.Group(prefix)

	// ── 需要 token 的路由 ──────────────────────────────────────────────────
	authG := g.Group("", c.remoteCheckLogin())

	// 完整用户信息
	authG.GET("/user/info", func(ctx *gin.Context) {
		userID := c.loginIDFromCtx(ctx)
		info, err := c.GetFullUserInfo(ctx.Request.Context(), userID)
		if err != nil {
			gowk.Response(ctx, http.StatusBadRequest, nil, err)
			return
		}
		gowk.Response(ctx, http.StatusOK, info, nil)
	})

	// ── OAuth2 / OIDC（无需 token） ────────────────────────────────────────
	g.POST("/oauth2/token", func(ctx *gin.Context) {
		var params struct {
			GrantType    string `form:"grant_type" binding:"required"`
			Code         string `form:"code"`
			RedirectURI  string `form:"redirect_uri"`
			ClientID     string `form:"client_id"`
			ClientSecret string `form:"client_secret"`
			RefreshToken string `form:"refresh_token"`
			Scope        string `form:"scope"`
			CodeVerifier string `form:"code_verifier"`
		}
		if err := ctx.ShouldBind(&params); err != nil {
			gowk.Response(ctx, http.StatusBadRequest, nil, err)
			return
		}
		resp, err := c.OAuth2Token(ctx.Request.Context(),
			params.GrantType, params.Code, params.RedirectURI,
			params.ClientID, params.ClientSecret, params.RefreshToken,
			params.Scope, params.CodeVerifier)
		if err != nil {
			gowk.Response(ctx, http.StatusBadRequest, nil, err)
			return
		}
		gowk.Response(ctx, http.StatusOK, resp, nil)
	})

	g.GET("/.well-known/openid_configuration", func(ctx *gin.Context) {
		resp, err := c.OIDCDiscovery(ctx.Request.Context())
		if err != nil {
			gowk.Response(ctx, http.StatusInternalServerError, nil, err)
			return
		}
		gowk.Response(ctx, http.StatusOK, resp, nil)
	})

	g.GET("/oidc/jwks", func(ctx *gin.Context) {
		resp, err := c.OIDCJwks(ctx.Request.Context())
		if err != nil {
			gowk.Response(ctx, http.StatusInternalServerError, nil, err)
			return
		}
		gowk.Response(ctx, http.StatusOK, resp, nil)
	})

	g.GET("/oidc/userinfo", func(ctx *gin.Context) {
		accessToken := c.bearerToken(ctx)
		if accessToken == "" {
			gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("access_token required"))
			return
		}
		resp, err := c.OIDCUserInfo(ctx.Request.Context(), accessToken)
		if err != nil {
			gowk.Response(ctx, http.StatusUnauthorized, nil, err)
			return
		}
		gowk.Response(ctx, http.StatusOK, resp, nil)
	})
}

// remoteCheckLogin 从 Authorization/X-Token 取 token，通过 gRPC CheckToken 验证，
// 将 userId 写入 gin.Context（key: gowk.ContextLoginIdKey）。
func (c *AuthClient) remoteCheckLogin() gin.HandlerFunc {
	unauthorized := &gowk.ErrorCode{Status: http.StatusUnauthorized, Code: http.StatusUnauthorized, Msg: "认证失败"}
	return func(ctx *gin.Context) {
		token := c.bearerToken(ctx)
		if token == "" {
			gowk.Fail(ctx, unauthorized)
			return
		}
		resp, err := c.CheckToken(ctx.Request.Context(), token)
		if err != nil {
			gowk.Fail(ctx, unauthorized)
			return
		}
		ctx.Set(gowk.ContextLoginIdKey, resp.UserId)
		ctx.Next()
	}
}

// bearerToken 从 Authorization: Bearer <token> 或 X-Token header 中提取 token。
func (c *AuthClient) bearerToken(ctx *gin.Context) string {
	auth := ctx.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ctx.GetHeader("X-Token")
}

// loginIDFromCtx 从 gin.Context 中取出由 remoteCheckLogin 写入的 userId。
func (c *AuthClient) loginIDFromCtx(ctx *gin.Context) int64 {
	v, _ := ctx.Get(gowk.ContextLoginIdKey)
	id, _ := v.(int64)
	return id
}
