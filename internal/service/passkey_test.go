package service

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPasskeyConfigDerivesPublicOriginAndRPID(t *testing.T) {
	t.Setenv("PASSKEY_ORIGINS", "https://auth.example.com/some/path")
	t.Setenv("PASSKEY_RP_ID", "")
	t.Setenv("PASSKEY_RP_DISPLAY_NAME", "")

	config, err := passkeyConfig()
	if err != nil {
		t.Fatalf("passkeyConfig returned error: %v", err)
	}
	if config.RPID != "auth.example.com" {
		t.Fatalf("RPID = %q, want auth.example.com", config.RPID)
	}
	if !reflect.DeepEqual(config.RPOrigins, []string{"https://auth.example.com"}) {
		t.Fatalf("RPOrigins = %#v", config.RPOrigins)
	}
	if config.RPDisplayName != "Auth" {
		t.Fatalf("RPDisplayName = %q, want Auth", config.RPDisplayName)
	}
}

func TestPasskeyConfigRejectsInsecurePublicOrigin(t *testing.T) {
	t.Setenv("PASSKEY_ORIGINS", "http://auth.example.com")
	if _, err := passkeyConfig(); err == nil {
		t.Fatal("passkeyConfig accepted an insecure public origin")
	}
}

func TestPasskeyConfigAllowsLocalHTTP(t *testing.T) {
	t.Setenv("PASSKEY_ORIGINS", "http://localhost:3030")
	t.Setenv("PASSKEY_RP_ID", "")
	config, err := passkeyConfig()
	if err != nil {
		t.Fatalf("passkeyConfig returned error: %v", err)
	}
	if config.RPID != "localhost" {
		t.Fatalf("RPID = %q, want localhost", config.RPID)
	}
}

func TestPasskeyCredentialRestoresAuthenticatorState(t *testing.T) {
	record := db2.AuthPasskeyCredential{
		CredentialID:   []byte("credential"),
		PublicKey:      []byte("public-key"),
		Transports:     `["internal","hybrid"]`,
		SignCount:      7,
		UserPresent:    true,
		UserVerified:   true,
		BackupEligible: true,
		BackupState:    true,
	}
	credential, err := passkeyCredential(record)
	if err != nil {
		t.Fatalf("passkeyCredential returned error: %v", err)
	}
	if credential.Authenticator.SignCount != 7 || !credential.Flags.UserVerified || len(credential.Transport) != 2 {
		t.Fatalf("credential state was not restored: %#v", credential)
	}
}

func TestPasskeyCredentialSummaryDoesNotExposeCredentialMaterial(t *testing.T) {
	created := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	lastUsed := created.Add(time.Hour)
	record := db2.AuthPasskeyCredential{
		ID:             7,
		Name:           "MacBook",
		DeviceInfo:     []byte(`{"platform":"macOS","user_agent":"Browser"}`),
		CredentialID:   []byte("credential-secret"),
		PublicKey:      []byte("public-key"),
		Transports:     `["internal"]`,
		Attachment:     "platform",
		BackupEligible: true,
		BackupState:    true,
		Created:        pgtype.Timestamptz{Time: created, Valid: true},
		LastUsedAt:     pgtype.Timestamptz{Time: lastUsed, Valid: true},
	}
	summary, err := passkeyCredentialSummary(record)
	if err != nil {
		t.Fatalf("passkeyCredentialSummary returned error: %v", err)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	jsonText := string(encoded)
	for _, forbidden := range []string{"credential_id", "credential-secret", "public_key", "public-key", "aaguid", "sign_count"} {
		if strings.Contains(jsonText, forbidden) {
			t.Fatalf("summary exposes %q: %s", forbidden, jsonText)
		}
	}
	if summary.ID != 7 || summary.Name != "MacBook" || summary.DeviceInfo.Platform != "macOS" || len(summary.Transports) != 1 || summary.LastUsedAt == nil {
		t.Fatalf("summary metadata is incomplete: %#v", summary)
	}
}

func TestNormalizePasskeyDeviceInfoTrimsAndLimitsBrowserMetadata(t *testing.T) {
	info := normalizePasskeyDeviceInfo(PasskeyDeviceInfo{
		UserAgent: "  Browser  ",
		Platform:  strings.Repeat("设", 101),
		Model:     "  Phone  ",
		Mobile:    true,
	})
	if info.UserAgent != "Browser" || info.Model != "Phone" || !info.Mobile {
		t.Fatalf("normalized device info = %#v", info)
	}
	if len([]rune(info.Platform)) != 100 {
		t.Fatalf("platform length = %d, want 100", len([]rune(info.Platform)))
	}
}

func TestValidateBrowserOrigin(t *testing.T) {
	t.Setenv("PASSKEY_ORIGINS", "https://auth.example.com,https://login.example.com:8443")

	for _, origin := range []string{"https://auth.example.com", "https://login.example.com:8443"} {
		if err := ValidateBrowserOrigin(origin); err != nil {
			t.Fatalf("ValidateBrowserOrigin(%q) returned error: %v", origin, err)
		}
	}
	for _, origin := range []string{"", "null", "https://evil.example.com", "https://auth.example.com/path"} {
		if err := ValidateBrowserOrigin(origin); err == nil {
			t.Fatalf("ValidateBrowserOrigin(%q) unexpectedly succeeded", origin)
		}
	}
}
