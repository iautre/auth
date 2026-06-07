package handler

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"runtime/debug"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const grpcServiceTokenHeader = "x-auth-service-token"

// RecoveryUnaryInterceptor 捕获 handler panic，转成 codes.Internal 错误返回，避免单个请求的
// panic 直接 crash 整个 auth 进程（grpc-go 默认不 recover handler panic）。
// 与 HTTP 侧 gowk.Recover() 对齐，gRPC 侧此前缺失同等保护。
func RecoveryUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				slog.ErrorContext(ctx, "gRPC handler panic recovered", "method", info.FullMethod, "panic", r, "stack", string(debug.Stack()))
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// RecoveryStreamInterceptor 是 RecoveryUnaryInterceptor 的 stream 版本。
func RecoveryStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				slog.ErrorContext(stream.Context(), "gRPC stream handler panic recovered", "method", info.FullMethod, "panic", r, "stack", string(debug.Stack()))
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(srv, stream)
	}
}

// healthMethodPrefix 是标准 gRPC 健康检查服务（grpc.health.v1.Health/Check、/Watch）的方法前缀。
// 健康探活（K8s gRPC probe / LB / grpc_health_probe / 二进制 grpc-healthcheck）不携带 service token，
// 必须放行，否则配置 token 后探活会被拒为 Unauthenticated。
const healthMethodPrefix = "/grpc.health.v1.Health/"

// ServiceTokenUnaryInterceptor protects auth gRPC methods with a shared service token.
// Empty token keeps local/dev deployments backward compatible and disables enforcement.
func ServiceTokenUnaryInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if token == "" || strings.HasPrefix(info.FullMethod, healthMethodPrefix) {
			return handler(ctx, req)
		}
		if !validServiceToken(ctx, token) {
			return nil, status.Error(codes.Unauthenticated, "invalid service token")
		}
		return handler(ctx, req)
	}
}

// ServiceTokenStreamInterceptor applies the same service-token check to streaming RPCs,
// including gRPC reflection and any future stream methods. The standard health service
// (grpc.health.v1.Health/Watch) is exempt so health probes can run without a token.
func ServiceTokenStreamInterceptor(token string) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if token == "" || strings.HasPrefix(info.FullMethod, healthMethodPrefix) {
			return handler(srv, stream)
		}
		if !validServiceToken(stream.Context(), token) {
			return status.Error(codes.Unauthenticated, "invalid service token")
		}
		return handler(srv, stream)
	}
}

func validServiceToken(ctx context.Context, expected string) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, candidate := range serviceTokenCandidates(md) {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func serviceTokenCandidates(md metadata.MD) []string {
	var values []string
	values = append(values, md.Get(grpcServiceTokenHeader)...)
	for _, auth := range md.Get("authorization") {
		if token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")); token != auth && token != "" {
			values = append(values, token)
		}
	}
	return values
}
