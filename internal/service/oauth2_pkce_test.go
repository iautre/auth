package service

import "testing"

func TestValidatePublicClientPKCE(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		challenge string
		method    string
		wantError bool
	}{
		{name: "public S256", challenge: "challenge", method: "S256"},
		{name: "public without challenge", method: "S256", wantError: true},
		{name: "public plain", challenge: "challenge", method: "plain", wantError: true},
		{name: "confidential without PKCE", secret: "server-secret"},
		{name: "confidential with PKCE", secret: "server-secret", challenge: "challenge", method: "S256"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePublicClientPKCE(test.secret, test.challenge, test.method)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %v", err, test.wantError)
			}
		})
	}
}
