package embed

import (
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetupMountsBasicAPIWithoutBrowserOrOAuthRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("AUTH_GRPC_ADDR", "127.0.0.1:1")
	router := gin.New()
	Setup(router, "/api/host/auth")

	var loginAPI, logoutAPI, browserPage, oauthRoute bool
	for _, registered := range router.Routes() {
		if registered.Path == "/api/host/auth/login" && registered.Method == "POST" {
			loginAPI = true
		}
		if registered.Path == "/api/host/auth/logout" && registered.Method == "POST" {
			logoutAPI = true
		}
		if registered.Path == "/api/host/auth/login" && registered.Method == "GET" {
			browserPage = true
		}
		if strings.Contains(registered.Path, "/oauth2/") || strings.Contains(registered.Path, "/oidc/") || strings.Contains(registered.Path, "/.well-known/") {
			oauthRoute = true
		}
	}
	if !loginAPI {
		t.Fatal("POST login API was not mounted")
	}
	if browserPage {
		t.Fatal("gRPC embed mode must not mount Auth's browser login page")
	}
	if !logoutAPI {
		t.Fatal("POST logout API was not mounted")
	}
	if oauthRoute {
		t.Fatal("gRPC embed mode must not proxy OAuth/OIDC routes")
	}
}
