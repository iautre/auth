package cmd

import (
	"context"

	"github.com/iautre/auth/internal/config"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/auth/migrations"
	"github.com/iautre/auth/pkg/authhttp"
	authpb "github.com/iautre/auth/pkg/proto"
	"github.com/iautre/gowk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func Run() {
	// 端口由 gowk 直接从 HTTP_SERVER_ADDR / GRPC_SERVER_ADDR 环境变量读取（默认值见 Dockerfile ENV），
	// 此处无需再读取或设置。

	// 注册数据库迁移：gowk 在连上 DB 后、对外服务前自动按版本顺序执行 migrations/*.sql。
	gowk.AddMigrations(migrations.FS, ".")

	// Create servers
	r := gowk.New()
	// 独立 HTTP 模式与第三方包内嵌模式共用同一个 Mount，不再分别注册路由。
	authhttp.Mount(r, authhttp.Options{
		Prefix:  config.AuthAPIPrefix(),
		MCPPath: "/mcp",
	})

	// recovery 必须在链首：先兜住 handler panic，再做 service-token 鉴权，避免 panic 直接 crash 进程。
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			handler.RecoveryUnaryInterceptor(),
			handler.ServiceTokenUnaryInterceptor(config.AuthGRPCToken()),
		),
		grpc.ChainStreamInterceptor(
			handler.RecoveryStreamInterceptor(),
			handler.ServiceTokenStreamInterceptor(config.AuthGRPCToken()),
		),
	)
	reflection.Register(server)
	grpcServer := &gowk.GrpcServer{Server: server}
	authServer := handler.NewAuthServiceServer(context.Background())
	authpb.RegisterAuthServiceServer(grpcServer.Server, authServer)

	// /health 由 gowk.New() 统一注册（存活探测，含 grpc 状态），此处不再重复。

	// Start both servers using unified API
	gowk.RunBoth(r, grpcServer)
}
