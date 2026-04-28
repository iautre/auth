package handler

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const grpcServiceTokenHeader = "x-auth-service-token"

// ServiceTokenUnaryInterceptor protects auth gRPC methods with a shared service token.
// Empty token keeps local/dev deployments backward compatible and disables enforcement.
func ServiceTokenUnaryInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if token == "" {
			return handler(ctx, req)
		}
		if !validServiceToken(ctx, token) {
			return nil, status.Error(codes.Unauthenticated, "invalid service token")
		}
		return handler(ctx, req)
	}
}

// ServiceTokenStreamInterceptor applies the same service-token check to streaming RPCs,
// including gRPC reflection and any future stream methods.
func ServiceTokenStreamInterceptor(token string) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if token == "" {
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
