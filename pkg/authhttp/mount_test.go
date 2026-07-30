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

func TestMountRegistersCompleteHTTPRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	module := authhttp.Mount(router, authhttp.Options{Prefix: "api/auth/"})
	if module == nil || module.Group == nil || module.CheckLogin == nil || module.CheckAdmin == nil {
		t.Fatal("Mount returned an incomplete module")
	}

	want := map[string]bool{
		"POST /api/auth/login":                                false,
		"POST /api/auth/mqtt/auth":                            false,
		"GET /api/auth/user/info":                             false,
		"POST /api/auth/user/:userId/reset-otp":               false,
		"GET /api/auth/oauth2/auth":                           false,
		"POST /api/auth/oauth2/token":                         false,
		"GET /api/auth/.well-known/openid_configuration":      false,
		"GET /api/auth/oidc/userinfo":                         false,
		"GET /api/auth/oidc/jwks":                             false,
		"POST /api/auth/oauth2/clients":                       false,
		"GET /api/auth/oauth2/clients":                        false,
		"GET /api/auth/oauth2/clients/:id":                    false,
		"PUT /api/auth/oauth2/clients/:id":                    false,
		"DELETE /api/auth/oauth2/clients/:id/disable":         false,
		"POST /api/auth/oauth2/clients/:id/regenerate-secret": false,
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
}

func TestMountPrefixIsUsedByOIDCDiscovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	authhttp.Mount(router, authhttp.Options{Prefix: "/embedded/auth"})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/embedded/auth/.well-known/openid_configuration", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response struct {
		Data struct {
			TokenEndpoint string `json:"token_endpoint"`
			JwksURI       string `json:"jwks_uri"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.HasSuffix(response.Data.TokenEndpoint, "/embedded/auth/oauth2/token") {
		t.Fatalf("token_endpoint = %q", response.Data.TokenEndpoint)
	}
	if !strings.HasSuffix(response.Data.JwksURI, "/embedded/auth/oidc/jwks") {
		t.Fatalf("jwks_uri = %q", response.Data.JwksURI)
	}
}
