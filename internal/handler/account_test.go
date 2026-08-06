package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/iautre/gowk"
)

func TestBrowserSameOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("PASSKEY_ORIGINS", "https://auth.example.com")
	router := gin.New()
	router.POST("/change", BrowserSameOrigin, func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) })

	allowed := httptest.NewRecorder()
	allowedRequest := httptest.NewRequest(http.MethodPost, "/change", strings.NewReader("{}"))
	allowedRequest.Header.Set("Origin", "https://auth.example.com")
	router.ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("allowed status = %d, want 204", allowed.Code)
	}

	blocked := httptest.NewRecorder()
	blockedRequest := httptest.NewRequest(http.MethodPost, "/change", strings.NewReader("{}"))
	blockedRequest.Header.Set("Origin", "https://evil.example.com")
	router.ServeHTTP(blocked, blockedRequest)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("blocked status = %d, want 403", blocked.Code)
	}
}

func TestLogoutClearsBrowserCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/logout", nil)
	ctx.Set(gowk.ContextTokenValueKey, "session-token")

	var users UserHandler
	users.Logout(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	cookie := recorder.Header().Get("Set-Cookie")
	for _, want := range []string{"oidc_jwt=", "Path=/", "Max-Age=0", "HttpOnly", "Secure"} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("Set-Cookie = %q, missing %q", cookie, want)
		}
	}
}
