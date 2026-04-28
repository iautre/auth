package dto

import (
	"testing"

	"github.com/iautre/auth/internal/db"
)

func TestBuildOAuth2ClientResponseHidesSecretByDefault(t *testing.T) {
	client := db.AuthOauth2Client{
		ID:     "client-id",
		Name:   "client-name",
		Secret: "secret-value",
	}

	resp := BuildOAuth2ClientResponse(client)
	if resp.Secret != "" {
		t.Fatalf("Secret = %q, want empty", resp.Secret)
	}
}

func TestBuildOAuth2ClientResponseCanIncludeSecret(t *testing.T) {
	client := db.AuthOauth2Client{
		ID:     "client-id",
		Name:   "client-name",
		Secret: "secret-value",
	}

	resp := BuildOAuth2ClientResponseWithSecret(client, true)
	if resp.Secret != "secret-value" {
		t.Fatalf("Secret = %q, want secret-value", resp.Secret)
	}
}
