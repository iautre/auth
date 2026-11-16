package cmd

import (
	"strings"

	"github.com/iautre/auth/internal/config"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/auth/pkg/authhttp"
	"github.com/iautre/gowk"
)

func Run() {
	// 端口由 gowk 直接从 HTTP_SERVER_ADDR 环境变量读取（默认值见 Dockerfile ENV），
	// 此处无需再读取或设置。

	r := gowk.New()
	// 基础认证 API 可被第三方包复用；OAuth/OIDC 协议入口只在需要充当
	// 授权服务器时显式挂载，避免进入宿主的 /api/.../auth 前缀。
	module := authhttp.MountAPI(r, authhttp.APIOptions{
		Prefix:  config.AuthAPIPrefix(),
		MCPPath: "/mcp",
	})
	loginURL := strings.TrimSuffix(module.Group.BasePath(), "/") + "/login"
	authhttp.MountOAuth(r, authhttp.OAuthOptions{LoginURL: loginURL})

	// Auth 内置浏览器页面只属于独立部署模式。
	module.Group.GET("/login", handler.OIDCLoginPageFor("/oauth2/authorize", "/oauth2/auth"))
	module.Group.GET("/account", handler.OAuth2BrowserLogin(loginURL), handler.AccountPage)

	// /health 由 gowk.New() 统一注册（存活探测），此处不再重复。
	gowk.RunHTTP(r)
}
