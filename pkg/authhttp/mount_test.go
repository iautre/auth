package authhttp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/pkg/authhttp"
)

func TestMountAPIRegistersOnlyApplicationRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	module := authhttp.MountAPI(router, authhttp.APIOptions{Prefix: "api/auth/"})
	if module == nil || module.Group == nil || module.CheckLogin == nil || module.CheckAdmin == nil {
		t.Fatal("Mount returned an incomplete module")
	}

	want := map[string]bool{
		"POST /api/auth/login":                     false,
		"POST /api/auth/mqtt/auth":                 false,
		"GET /api/auth/user/info":                  false,
		"PUT /api/auth/user/profile":               false,
		"POST /api/auth/logout":                    false,
		"GET /api/auth/otp/credentials":            false,
		"POST /api/auth/otp/enrollment/begin":      false,
		"POST /api/auth/otp/enrollment/finish":     false,
		"DELETE /api/auth/otp/credentials/:id":     false,
		"GET /api/auth/passkey/status":             false,
		"GET /api/auth/passkey/credentials":        false,
		"PATCH /api/auth/passkey/credentials/:id":  false,
		"DELETE /api/auth/passkey/credentials/:id": false,
		"POST /api/auth/passkey/register/begin":    false,
		"POST /api/auth/passkey/register/finish":   false,
		"POST /api/auth/passkey/login/begin":       false,
		"POST /api/auth/passkey/login/finish":      false,
		"POST /api/auth/user/:userId/reset-otp":    false,
	}

	for _, registered := range router.Routes() {
		key := registered.Method + " " + registered.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for route, found := range want {
		if !found {
			t.Errorf("route %s was not mounted", route)
		}
	}
	for _, registered := range router.Routes() {
		if strings.Contains(registered.Path, "/oauth2/") || strings.Contains(registered.Path, "/oidc/") || strings.Contains(registered.Path, "/.well-known/") {
			t.Errorf("OAuth/OIDC route %s %s must not be mounted by MountAPI", registered.Method, registered.Path)
		}
		if registered.Method == http.MethodGet && (registered.Path == "/api/auth/login" || registered.Path == "/api/auth/account") {
			t.Errorf("browser page %s %s must not be mounted by MountAPI", registered.Method, registered.Path)
		}
	}
}

func TestMountOAuthRegistersProtocolRoutesAndDiscovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	authhttp.MountOAuth(router, authhttp.OAuthOptions{})

	want := map[string]bool{
		"GET /oauth2/authorize":                      false,
		"GET /oauth2/auth":                           false,
		"POST /oauth2/token":                         false,
		"GET /.well-known/openid-configuration":      false,
		"POST /oidc/token":                           false,
		"GET /oidc/userinfo":                         false,
		"GET /oidc/jwks":                             false,
		"POST /oauth2/clients":                       false,
		"GET /oauth2/clients":                        false,
		"GET /oauth2/clients/:id":                    false,
		"PUT /oauth2/clients/:id":                    false,
		"DELETE /oauth2/clients/:id/disable":         false,
		"POST /oauth2/clients/:id/regenerate-secret": false,
	}
	for _, registered := range router.Routes() {
		key := registered.Method + " " + registered.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for route, found := range want {
		if !found {
			t.Errorf("route %s was not mounted", route)
		}
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if origin := recorder.Header().Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want *", origin)
	}

	var response struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		Data          any    `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Issuer == "" {
		t.Fatal("issuer is empty")
	}
	if !strings.HasSuffix(response.TokenEndpoint, "/oauth2/token") {
		t.Fatalf("token_endpoint = %q", response.TokenEndpoint)
	}
	if response.Data != nil {
		t.Fatalf("standard discovery must not use gowk data envelope: %#v", response.Data)
	}
}

func TestMountOAuthProtocolRoutesStayAtRoot(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	authhttp.MountAPI(router, authhttp.APIOptions{Prefix: "/api/auth"})
	authhttp.MountOAuth(router, authhttp.OAuthOptions{})

	want := map[string]bool{
		"GET /oauth2/authorize":                 false,
		"POST /oauth2/token":                    false,
		"GET /.well-known/openid-configuration": false,
	}
	for _, registered := range router.Routes() {
		key := registered.Method + " " + registered.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
		if strings.HasPrefix(registered.Path, "/api/auth/oauth2/") || strings.HasPrefix(registered.Path, "/api/auth/oidc/") {
			t.Errorf("protocol route must not inherit API prefix: %s %s", registered.Method, registered.Path)
		}
	}
	for route, found := range want {
		if !found {
			t.Errorf("route %s was not mounted at the root", route)
		}
	}
}

func TestMountOAuthUsesHostLoginURLOrReturnsUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redirectRouter := gin.New()
	authhttp.MountOAuth(redirectRouter, authhttp.OAuthOptions{LoginURL: "/login"})
	redirect := httptest.NewRecorder()
	redirectRouter.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=test", nil))
	if redirect.Code != http.StatusFound || !strings.HasPrefix(redirect.Header().Get("Location"), "/login?return_to=") {
		t.Fatalf("redirect status/location = %d/%q", redirect.Code, redirect.Header().Get("Location"))
	}

	apiRouter := gin.New()
	authhttp.MountOAuth(apiRouter, authhttp.OAuthOptions{})
	unauthorized := httptest.NewRecorder()
	request := "/oauth2/authorize?response_type=code&client_id=test&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid"
	apiRouter.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, request, nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("status without LoginURL = %d, want 401", unauthorized.Code)
	}
}

func TestMountOAuthRejectsExternalLoginURL(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected external LoginURL to panic")
		}
	}()
	authhttp.MountOAuth(gin.New(), authhttp.OAuthOptions{LoginURL: "https://evil.example/login"})
}
