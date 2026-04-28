package service

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

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
