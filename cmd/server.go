package cmd

import (
	"context"

	"github.com/iautre/auth/internal/config"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/auth/internal/route"
	authpb "github.com/iautre/auth/pkg/proto"
	"github.com/iautre/gowk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func Run() {
	// 端口由 gowk 直接从 HTTP_SERVER_ADDR / GRPC_SERVER_ADDR 环境变量读取（默认值见 Dockerfile ENV），
	// 此处无需再读取或设置。

	// Create servers
	r := gowk.New()
	apiGroup := r.Group(config.AuthAPIPrefix())
	// 独立部署模式：/login 使用 HTTP UserHandler（签发 JWT ID Token）。
	// embed 模式下 /login 由 embed.Setup 注册为 mw.loginHandler（签发 gowk native token）。
	userHandler := handler.NewUserHandler(context.Background())
	apiGroup.POST("/login", userHandler.Login)
	// EMQX HTTP 认证回调：校验 native 登录 token / OAuth2 access_token。
	mqttHandler := handler.NewMqttHandler(context.Background())
	apiGroup.POST("/mqtt/auth", mqttHandler.Auth)
	route.Router(apiGroup)

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
