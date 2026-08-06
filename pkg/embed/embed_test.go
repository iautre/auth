package embed

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetupMountsBrowserLoginPageForRemoteSDK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("AUTH_GRPC_ADDR", "127.0.0.1:1")
	router := gin.New()
	Setup(router, "/api/host/auth")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/host/auth/login?return_to=%2Fdashboard%2Fworkplace", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	for _, want := range []string{
		`data-login-path="/api/host/auth/login"`,
		`data-token-storage-key="token"`,
		`data-passkey-enabled="false"`,
	} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Fatalf("browser login page is missing %q", want)
		}
	}
}
