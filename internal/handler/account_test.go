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

	// 没有 Origin 的请求不是浏览器跨站请求（curl / 服务端调用），不构成 CSRF 面，应放行。
	direct := httptest.NewRecorder()
	directRequest := httptest.NewRequest(http.MethodPost, "/change", strings.NewReader("{}"))
	router.ServeHTTP(direct, directRequest)
	if direct.Code != http.StatusNoContent {
		t.Fatalf("no-origin status = %d, want 204", direct.Code)
	}
}

// 清 cookie 的属性必须与设置时一致，否则浏览器不会覆盖原 cookie。
// Secure 跟随部署协议：https 下带，http 下不带（带了浏览器会忽略）。
func TestLogoutClearsBrowserCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	original := gowk.CookieSecure()
	t.Cleanup(func() { gowk.SetCookieSecure(original) })

	for _, secure := range []bool{true, false} {
		gowk.SetCookieSecure(secure)

		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/logout", nil)
		ctx.Set(gowk.ContextTokenValueKey, "session-token")

		var users UserHandler
		users.Logout(ctx)
		if recorder.Code != http.StatusOK {
			t.Fatalf("secure=%v status = %d, want 200", secure, recorder.Code)
		}

		cookie := recorder.Header().Get("Set-Cookie")
		for _, want := range []string{"oidc_jwt=", "Path=/", "Max-Age=0", "HttpOnly"} {
			if !strings.Contains(cookie, want) {
				t.Fatalf("secure=%v Set-Cookie = %q, missing %q", secure, cookie, want)
			}
		}
		if got := strings.Contains(cookie, "Secure"); got != secure {
			t.Fatalf("secure=%v Set-Cookie = %q, Secure 标记不符", secure, cookie)
		}
	}
}
