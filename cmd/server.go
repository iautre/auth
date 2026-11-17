package cmd

import (
	"context"
	"log"

	"github.com/iautre/auth/internal/config"
	"github.com/iautre/auth/pkg/authhttp"
	"github.com/iautre/gowk"
)

func Run() {
	// 端口由 gowk 直接从 HTTP_SERVER_ADDR 环境变量读取（默认值见 Dockerfile ENV），
	// 此处无需再读取或设置。
	r := gowk.New()

	// Auth 的用户、OTP、passkey、OAuth2 client 与签名私钥全部依赖 PostgreSQL。
	// DATABASE_ENABLED=false 时进程即使起来也只会一路报错，这里直接拒绝启动。
	if gowk.DB(context.Background()) == nil {
		log.Fatal("auth 需要 PostgreSQL：请配置 DATABASE_DSN 并保持 DATABASE_ENABLED=true")
	}

	// 独立部署：业务 API + OAuth2/OIDC 协议端点 + 第三方 OIDC 登录 + 内置页面。
	// 登录页地址按 {APIPrefix}/login 推导，协议端点与 /federated/* 固定在根路径。
	authhttp.Setup(r, authhttp.SetupOptions{
		APIPrefix: config.AuthAPIPrefix(),
		MCPPath:   "/mcp",
		OAuth:     true,
		Federated: config.FederatedEnabled(),
		Pages:     true,
	})

	// /health 由 gowk.New() 统一注册（存活探测），此处不再重复。
	gowk.RunHTTP(r)
}
