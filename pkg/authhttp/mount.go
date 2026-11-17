// Package authhttp exposes Auth's application API and OAuth/OIDC protocol
// surface as separate reusable Gin modules.
package authhttp

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/auth/internal/mcpserver"
	"github.com/iautre/auth/internal/route"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/migrations"
	"github.com/iautre/auth/pkg/authctx"
	"github.com/iautre/auth/pkg/constant"
	"github.com/iautre/gowk"
)

// APIOptions controls where Auth's application-facing HTTP API is exposed.
type APIOptions struct {
	// Prefix is prepended to auth REST endpoints. Empty exposes them at the root.
	Prefix string
	// MCPPath mounts the auth MCP endpoint on the same engine. Empty disables MCP.
	MCPPath string
}

// OAuthOptions controls the optional OAuth2/OIDC authorization-server surface.
type OAuthOptions struct {
	// LoginURL is the browser login page owned by the mounting application.
	// Empty makes anonymous authorization requests return 401 instead of redirecting.
	LoginURL string
}

// Module contains the mounted route group and middleware that host applications can
// reuse on their own business routes.
type Module struct {
	Group *gin.RouterGroup
	// CheckLogin 只校验 token 并把登录 ID 写入 gowk.ContextLoginIdKey，不查库。
	CheckLogin gin.HandlerFunc
	// UserAuth 在 CheckLogin 之上按登录 ID 查出用户，并写入 authctx.ContextUserKey，
	// 供业务代码用 authctx.ContextUser(ctx) 取 Id / Nickname / Group。
	UserAuth gin.HandlerFunc
	// CheckAdmin 要求当前用户属于管理员组。
	CheckAdmin gin.HandlerFunc
}

// MountAPI injects Auth's application-facing HTTP API into router.
// Auth migrations are registered automatically; database/Redis connections and process lifecycle
// remain the host application's responsibility.
func MountAPI(router *gin.Engine, options APIOptions) *Module {
	migrations.Register()

	group := router.Group(normalizePath(options.Prefix))
	ctx := context.Background()

	userHandler := handler.NewUserHandler(ctx)
	group.POST("/login", userHandler.Login)

	mqttHandler := handler.NewMqttHandler(ctx)
	group.POST("/mqtt/auth", mqttHandler.Auth)

	route.API(group)

	if options.MCPPath != "" {
		gowk.SetupMCP(router, normalizePath(options.MCPPath), mcpserver.NewProvider(), gowk.CheckLogin)
	}

	return &Module{
		Group:      group,
		CheckLogin: gowk.CheckLogin,
		UserAuth:   userAuth,
		CheckAdmin: handler.AdminMiddleware,
	}
}

// MountOAuth explicitly enables the OAuth2/OIDC authorization-server surface.
// It is intentionally separate from MountAPI so ordinary host applications do
// not expose protocol endpoints below their business API prefix.
func MountOAuth(router *gin.Engine, options OAuthOptions) *Module {
	migrations.Register()
	// OAuth/OIDC protocol endpoints have fixed conventional root paths. They are
	// deliberately not mountable below an application API prefix: doing so would
	// produce surprising paths and make issuer/discovery semantics ambiguous.
	group := router.Group("")
	route.OAuth(group, validateLoginURL(options.LoginURL))
	return &Module{
		Group:      group,
		CheckLogin: gowk.CheckLogin,
		UserAuth:   userAuth,
		CheckAdmin: handler.AdminMiddleware,
	}
}

// userAuth 把登录 ID 解析成用户对象写入上下文。
// 前置的 CheckLogin 只负责验 token，不查库；需要昵称/分组等信息的业务路由在此之后取用。
func userAuth(ctx *gin.Context) {
	loginId := gowk.LoginId(ctx)
	if loginId <= 0 {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError(constant.ErrAuthRequired))
		return
	}

	var userService service.UserService
	user, err := userService.GetById(ctx, loginId)
	if err != nil {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError(constant.ErrInvalidToken))
		return
	}

	ctx.Set(authctx.ContextUserKey, &authctx.User{
		Id:       user.ID,
		Nickname: user.Nickname.String,
		Group:    user.Group.String,
	})
}

func validateLoginURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || parsed.RawQuery != "" {
		panic("authhttp: LoginURL must be a same-origin relative path without query or fragment")
	}
	return raw
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return ""
	}
	path = "/" + strings.Trim(path, "/")
	return path
}
