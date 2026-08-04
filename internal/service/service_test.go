package service

import (
	"context"
	"testing"

	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestOIDCDiscoveryUsesExplicitHTTPPrefix(t *testing.T) {
	discovery := DefaultOIDCService().GetDiscoveryDocumentWithPrefix("api/auth/")
	want := gowk.BaseURL() + "/api/auth/oidc/token"
	if discovery.TokenEndpoint != want {
		t.Fatalf("TokenEndpoint = %q, want %q", discovery.TokenEndpoint, want)
	}
}

func TestBuildTokenResponseUsesAccessTTL(t *testing.T) {
	var svc OAuth2Service

	resp, err := svc.buildTokenResponse(
		context.Background(),
		"access-token",
		"refresh-token",
		pgtype.Text{String: "profile", Valid: true},
		900,
		false,
		0,
		"",
		"",
	)
	if err != nil {
		t.Fatalf("buildTokenResponse returned error: %v", err)
	}
	if resp.ExpiresIn != 900 {
		t.Fatalf("ExpiresIn = %d, want 900", resp.ExpiresIn)
	}
}
