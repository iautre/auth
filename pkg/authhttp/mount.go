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
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
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
	// MCPPath 是 Auth 自己挂载的 MCP 端点路径。非空时同时暴露它的 RFC 9728
	// 保护资源元数据，第三方 MCP 客户端据此发现本授权服务器。
	MCPPath string
	// ProtectedResourcePath 只发布该资源路径的 RFC 9728 元数据，不注册 Auth
	// 自己的 MCP 端点。宿主自己实现 /mcp 时用这一项，避免与内置端点撞路径。
	// 为空时元数据按 MCPPath 计算，与旧行为一致。
	ProtectedResourcePath string
	// DeviceFlow 为真时挂载 RFC 8628 设备授权端点（device_authorization / poll / 确认页）。
	DeviceFlow bool
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
	// 过期数据清理：仅依赖 gowk.DB，未连接数据库时 runCleanup 自带跳过逻辑，
	// 因此可以安全地在任何挂载路径下启动。重复挂载由 internal 的 once 保护。
	service.StartCleanup()

	migrations.Register()

	group := router.Group(normalizePath(options.Prefix))
	ctx := context.Background()

	userHandler := handler.NewUserHandler(ctx)
	group.POST("/login", userHandler.Login)

	mqttHandler := handler.NewMqttHandler(ctx)
	group.POST("/mqtt/auth", mqttHandler.Auth)

	route.API(group)

	if options.MCPPath != "" {
		mcpPath := normalizePath(options.MCPPath)
		// 线上 nginx 经 docker 网络转发（非回环），SDK 默认的 DNS rebinding 保护
		// 不会误伤，保持开启即可。两个选项仍需显式给出——传 opts 会整体替换默认值。
		gowk.SetupMCPWithOptions(router, mcpPath, mcpserver.NewProvider(), &mcp.StreamableHTTPOptions{
			Stateless:                    true,
			PropagateRequestCancellation: true,
		}, handler.MCPAuth(gowk.BaseURL()+handler.ProtectedResourceMetadataPath(mcpPath)))
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
	route.OAuth(group, validateLoginURL(options.LoginURL), normalizePath(options.MCPPath), normalizePath(options.ProtectedResourcePath), options.DeviceFlow)
	return &Module{
		Group:      group,
		CheckLogin: gowk.CheckLogin,
		UserAuth:   userAuth,
		CheckAdmin: handler.AdminMiddleware,
	}
}

// MountFederated enables third-party OIDC login: auth acts as a relying party
// and accepts sign-ins from providers configured in the admin page.
// Paths live at the root (/federated/...) because callback URLs must be
// registered with each provider and cannot follow the host's API prefix.
func MountFederated(router *gin.Engine, options OAuthOptions) *Module {
	migrations.Register()
	group := router.Group("")
	route.Federated(group, validateLoginURL(options.LoginURL))
	service.WarmFederatedProviders()
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
