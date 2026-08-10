package client

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/gowk"
)

// MountRemote 将 Auth 的基础 HTTP API 以 gRPC 为后端挂载到 prefix。
// 登录接口（POST prefix/login）由 embed.Setup 注册；OAuth/OIDC 协议入口
// 始终由独立 Auth Service 暴露，不代理到宿主应用的业务 API 前缀。
//
//	GET  /user/info — 获取完整用户信息（需 token）
//	POST /logout    — 撤销当前 token（需 token）
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

	authG.POST("/logout", func(ctx *gin.Context) {
		if err := c.Logout(ctx.Request.Context(), c.bearerToken(ctx)); err != nil {
			gowk.Response(ctx, http.StatusUnauthorized, nil, err)
			return
		}
		gowk.Response(ctx, http.StatusOK, map[string]string{"message": "logged out"}, nil)
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
