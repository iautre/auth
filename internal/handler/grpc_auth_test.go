package handler

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestServiceTokenUnaryInterceptorAllowsWhenTokenUnset(t *testing.T) {
	interceptor := ServiceTokenUnaryInterceptor("")

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

func TestServiceTokenUnaryInterceptorRejectsMissingToken(t *testing.T) {
	interceptor := ServiceTokenUnaryInterceptor("secret")

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err == nil {
		t.Fatal("expected missing token to be rejected")
	}
}

func TestServiceTokenUnaryInterceptorAcceptsServiceTokenHeader(t *testing.T) {
	interceptor := ServiceTokenUnaryInterceptor("secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(grpcServiceTokenHeader, "secret"))

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

func TestServiceTokenUnaryInterceptorAcceptsBearerToken(t *testing.T) {
	interceptor := ServiceTokenUnaryInterceptor("secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer secret"))

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

func TestServiceTokenStreamInterceptorRejectsMissingToken(t *testing.T) {
	interceptor := ServiceTokenStreamInterceptor("secret")
	stream := fakeServerStream{ctx: context.Background()}

	err := interceptor(nil, stream, &grpc.StreamServerInfo{}, func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected missing token to be rejected")
	}
}

func TestServiceTokenStreamInterceptorAcceptsServiceTokenHeader(t *testing.T) {
	interceptor := ServiceTokenStreamInterceptor("secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(grpcServiceTokenHeader, "secret"))
	stream := fakeServerStream{ctx: ctx}

	err := interceptor(nil, stream, &grpc.StreamServerInfo{}, func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f fakeServerStream) Context() context.Context { return f.ctx }

func (f fakeServerStream) RecvMsg(m interface{}) error { return io.EOF }

func (f fakeServerStream) SendMsg(m interface{}) error { return nil }
