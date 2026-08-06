package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iautre/auth/pkg/dto"
)

func TestAuthenticationMethodMustRemain(t *testing.T) {
	for _, test := range []struct {
		otp, passkey int64
		want         bool
	}{
		{otp: 0, passkey: 0, want: false},
		{otp: 1, passkey: 0, want: true},
		{otp: 0, passkey: 1, want: true},
		{otp: 2, passkey: 3, want: true},
	} {
		if got := authenticationMethodRemains(test.otp, test.passkey); got != test.want {
			t.Fatalf("authenticationMethodRemains(%d, %d) = %t, want %t", test.otp, test.passkey, got, test.want)
		}
	}
}

func TestOTPAuthURLContainsStandardParameters(t *testing.T) {
	result := otpAuthURL("Auth Example", "little@example.com", "ABCDEFGHIJKLMNOP")
	for _, want := range []string{"otpauth://totp/", "secret=ABCDEFGHIJKLMNOP", "issuer=Auth+Example", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(result, want) {
			t.Fatalf("otpAuthURL is missing %q: %s", want, result)
		}
	}
}

func TestOTPCredentialSummaryDoesNotExposeSecret(t *testing.T) {
	now := time.Now()
	summary := OTPCredentialSummary{ID: 1, Name: "Phone", LastUsedAt: &now, Created: now}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal OTP summary: %v", err)
	}
	if strings.Contains(string(encoded), "secret") {
		t.Fatalf("OTP summary exposes secret field: %s", encoded)
	}
}

func TestUpdateProfileRejectsInvalidValuesBeforeDatabase(t *testing.T) {
	var users UserService
	for _, params := range []struct {
		phone, email, nickname string
	}{
		{phone: "123", email: "little@example.com", nickname: "Little"},
		{phone: "13800138000", email: "not-an-email", nickname: "Little"},
		{phone: "13800138000", email: "little@example.com", nickname: ""},
	} {
		_, err := users.UpdateProfile(t.Context(), 1, dto.ProfileUpdateParams{
			Phone: params.phone, Email: params.email, Nickname: params.nickname,
		})
		if err == nil {
			t.Fatalf("UpdateProfile accepted invalid values: %#v", params)
		}
	}
}
