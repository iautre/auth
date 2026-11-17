package service

import (
	"slices"
	"strings"
	"testing"
)

// 标准 OIDC 客户端靠这三个字段决定如何认证、能否用 PKCE、以及解析哪些 claims。
// 缺失时 Java / Node 客户端会按规范默认值只发 client_secret_basic。
func TestDiscoveryAdvertisesClientAuthAndPKCE(t *testing.T) {
	var svc OIDCService
	doc := svc.GetDiscoveryDocument()

	if !slices.Contains(doc.TokenEndpointAuthMethodsSupported, "client_secret_basic") ||
		!slices.Contains(doc.TokenEndpointAuthMethodsSupported, "client_secret_post") {
		t.Fatalf("token_endpoint_auth_methods_supported = %v", doc.TokenEndpointAuthMethodsSupported)
	}
	if !slices.Contains(doc.CodeChallengeMethodsSupported, "S256") {
		t.Fatalf("code_challenge_methods_supported = %v", doc.CodeChallengeMethodsSupported)
	}
	for _, claim := range []string{"sub", "email", "phone_number"} {
		if !slices.Contains(doc.ClaimsSupported, claim) {
			t.Errorf("claims_supported 缺少 %q", claim)
		}
	}
	if doc.TokenEndpoint != doc.Issuer+"/oauth2/token" {
		t.Errorf("token_endpoint = %q, 未按 issuer 拼接", doc.TokenEndpoint)
	}
}

// 接入方靠 discovery 发现登出、撤销、内省端点。缺任何一个字段，
// 标准客户端就只能自己拼地址，或者干脆放弃登出联动。
func TestDiscoveryAdvertisesSessionAndTokenManagement(t *testing.T) {
	var svc OIDCService
	doc := svc.GetDiscoveryDocument()

	endpoints := map[string]string{
		"end_session_endpoint":   doc.EndSessionEndpoint,
		"revocation_endpoint":    doc.RevocationEndpoint,
		"introspection_endpoint": doc.IntrospectionEndpoint,
	}
	for field, got := range endpoints {
		if !strings.HasPrefix(got, doc.Issuer+"/") {
			t.Errorf("%s = %q, 未按 issuer 拼接", field, got)
		}
	}
	if !slices.Contains(doc.RevocationEndpointAuthMethodsSupported, "client_secret_basic") {
		t.Errorf("revocation_endpoint_auth_methods_supported = %v", doc.RevocationEndpointAuthMethodsSupported)
	}
	if !slices.Contains(doc.IntrospectionEndpointAuthMethodsSupported, "client_secret_basic") {
		t.Errorf("introspection_endpoint_auth_methods_supported = %v", doc.IntrospectionEndpointAuthMethodsSupported)
	}
}
