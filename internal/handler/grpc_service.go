package handler

import (
	"context"

	"github.com/iautre/auth/pkg/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// AuthServiceServer implements the AuthService gRPC interface
type AuthServiceServer struct {
	proto.UnimplementedAuthServiceServer
	Handler *GrpcHandler
}

// NewAuthServiceServer creates a new AuthServiceServer
func NewAuthServiceServer(ctx context.Context) *AuthServiceServer {
	return &AuthServiceServer{
		Handler: NewGrpcHandler(ctx),
	}
}

// OAuth2Token handles OAuth2 token endpoint
func (s *AuthServiceServer) OAuth2Token(ctx context.Context, req *proto.OAuth2TokenRequest) (*proto.OAuth2TokenResponse, error) {
	return s.Handler.OAuth2Token(ctx, req)
}

// OIDCUserInfo handles OIDC userinfo endpoint
func (s *AuthServiceServer) OIDCUserInfo(ctx context.Context, req *proto.OIDCUserInfoRequest) (*proto.OIDCUserInfoResponse, error) {
	return s.Handler.OIDCUserInfo(ctx, req)
}

// OIDCDiscovery handles OIDC discovery endpoint
func (s *AuthServiceServer) OIDCDiscovery(ctx context.Context, req *emptypb.Empty) (*proto.OIDCDiscoveryResponse, error) {
	return s.Handler.OIDCDiscovery(ctx, req)
}

// OIDCJwks handles OIDC JWKS endpoint
func (s *AuthServiceServer) OIDCJwks(ctx context.Context, req *emptypb.Empty) (*proto.OIDCJwksResponse, error) {
	return s.Handler.OIDCJwks(ctx, req)
}
