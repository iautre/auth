package authhttp

import (
	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/auth/internal/service"
)

// SetupOptions 描述一次完整的 Auth 挂载。
type SetupOptions struct {
	// APIPrefix 是业务 API 的前缀，空表示挂在根路径。
	APIPrefix string
	// MCPPath 挂载 Auth 的 MCP 端点，空表示关闭。
	MCPPath string
	// ProtectedResourcePath 只发布该资源路径的 RFC 9728 元数据，不注册 Auth
	// 自己的 MCP 端点。宿主有自己的 /mcp 时用它，配合 MCPAuth 完成鉴权。
	ProtectedResourcePath string
	// DeviceFlow 为真时挂载 RFC 8628 设备授权端点，供没有浏览器/回调地址的客户端
	// （CLI、SSH、容器、CI、对话中的 agent）完成授权。
	DeviceFlow bool
	// OAuth 为真时同时挂载 OAuth2/OIDC 协议端点（固定根路径）。
	OAuth bool
	// Federated 为真时挂载第三方 OIDC 登录端点（固定根路径 /federated/...），
	// 让终端用户可以用 Google/GitLab/Keycloak 等外部账号登录。
	Federated bool
	// LoginURL 是 OAuth 无会话时浏览器跳转的登录页，必须是同源相对路径。
	// 留空且 Pages 为真时推导为 {APIPrefix}/login；Pages 也为假则不做跳转，直接返回 401。
	LoginURL string
	// Pages 为真时注册 Auth 自带的登录页与账号中心，挂在 {APIPrefix} 下。
	Pages bool
}

// Setup 一次性挂载 Auth：业务 API 始终挂载，协议端点与内置页面按开关决定。
// 返回的 Module 提供中间件，供宿主在自己的业务路由上复用。
func Setup(router *gin.Engine, options SetupOptions) *Module {
	// 显式配置 OAUTH2_TOKEN_CACHE=redis 时校验缓存后端可达，不可达则终止启动：
	// 静默退化成无缓存会让"配了 Redis"这个判断失真。
	if err := service.InitTokenCache(); err != nil {
		panic("authhttp: " + err.Error())
	}

	module := MountAPI(router, APIOptions{
		Prefix:  options.APIPrefix,
		MCPPath: options.MCPPath,
	})

	prefix := normalizePath(options.APIPrefix)
	loginURL := options.LoginURL
	if loginURL == "" && options.Pages {
		loginURL = prefix + "/login"
	}

	if options.OAuth {
		MountOAuth(router, OAuthOptions{
			LoginURL:              loginURL,
			MCPPath:               options.MCPPath,
			ProtectedResourcePath: options.ProtectedResourcePath,
			DeviceFlow:            options.DeviceFlow,
		})
	}

	if options.Federated {
		MountFederated(router, OAuthOptions{LoginURL: loginURL})
	}

	if options.Pages {
		module.Group.GET("/login", handler.OIDCLoginPageFor("/oauth2/authorize", "/admin/settings", "/admin/providers"))
		module.Group.GET("/account", handler.OAuth2BrowserLogin(loginURL), handler.AccountPage)
		// 后台分两块：个人设置（/account）与系统设置（/admin/settings）。
		// 系统设置含第三方登录、注册开关、用户管理，只有管理员能进。
		// 未登录直接 302 到登录页，登录后回跳；避免浏览器拿到 401。
		module.Group.GET("/admin/settings",
			handler.OAuth2BrowserLogin(loginURL),
			module.CheckAdmin,
			handler.SettingsPage,
		)
		// 旧地址保留跳转，避免已有书签失效。
		module.Group.GET("/admin/providers",
			handler.OAuth2BrowserLogin(loginURL),
			module.CheckAdmin,
			handler.ProvidersPageRedirect,
		)
	}

	return module
}
