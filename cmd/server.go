package cmd

import (
	"github.com/iautre/auth/internal/config"
	"github.com/iautre/auth/pkg/authhttp"
	"github.com/iautre/gowk"
)

func Run() {
	// 端口由 gowk 直接从 HTTP_SERVER_ADDR 环境变量读取（默认值见 Dockerfile ENV），
	// 此处无需再读取或设置。
	r := gowk.New()

	// 独立部署：业务 API + OAuth2/OIDC 协议端点 + 内置登录页与账号中心。
	// 登录页地址按 {APIPrefix}/login 推导，协议端点固定在根路径。
	authhttp.Setup(r, authhttp.SetupOptions{
		APIPrefix: config.AuthAPIPrefix(),
		MCPPath:   "/mcp",
		OAuth:     true,
		Pages:     true,
	})

	// /health 由 gowk.New() 统一注册（存活探测），此处不再重复。
	gowk.RunHTTP(r)
}
