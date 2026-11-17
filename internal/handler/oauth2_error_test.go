package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
)

func newTestContext(method, target string) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, nil)
	return ctx, recorder
}

func decodeOAuthBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是 OAuth 标准错误体: %v（原文 %q）", err, recorder.Body.String())
	}
	return body
}

// 客户端认证失败必须带 401，其余错误按调用方给的兜底码输出。
// 两者混为一谈会让第三方库无法区分"凭据错"和"授权码错"。
func TestWriteOAuthErrorMapsStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid_client 保留 401",
			err:        &service.OAuthError{Code: service.OAuthErrInvalidClient, Description: "bad secret", Status: http.StatusUnauthorized},
			wantStatus: http.StatusUnauthorized,
			wantCode:   service.OAuthErrInvalidClient,
		},
		{
			name:       "普通错误走兜底码",
			err:        errors.New("boom"),
			wantStatus: http.StatusBadRequest,
			wantCode:   service.OAuthErrInvalidGrant,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, recorder := newTestContext(http.MethodPost, "/oauth2/token")
			writeOAuthError(ctx, test.err, service.OAuthErrInvalidGrant, http.StatusBadRequest)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if body := decodeOAuthBody(t, recorder); body["error"] != test.wantCode {
				t.Fatalf("error = %q, want %q", body["error"], test.wantCode)
			}
			if recorder.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", recorder.Header().Get("Cache-Control"))
			}
		})
	}
}

// redirect_uri 已确认可信后，参数错误应带回客户端并保留 state，
// 否则接入方既不知道失败原因，也无法把响应匹配回自己的请求。
func TestRedirectOAuthErrorKeepsStateAndReason(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, recorder := newTestContext(http.MethodGet, "/oauth2/authorize")
	redirectOAuthError(ctx, "https://client.example/cb?tenant=1", "st-42", service.OAuthErrInvalidScope, "phone not allowed")

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	location := recorder.Header().Get("Location")
	for _, want := range []string{
		"https://client.example/cb?",
		"error=invalid_scope",
		"state=st-42",
		"error_description=phone+not+allowed",
		"tenant=1",
	} {
		if !strings.Contains(location, want) {
			t.Errorf("Location = %q, 缺少 %q", location, want)
		}
	}
}

func TestWriteBearerErrorSetsChallenge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, recorder := newTestContext(http.MethodGet, "/oidc/userinfo")
	writeBearerError(ctx, "invalid_token", "access token is invalid or expired")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	challenge := recorder.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Bearer ") || !strings.Contains(challenge, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate = %q", challenge)
	}
	if body := decodeOAuthBody(t, recorder); body["error"] != "invalid_token" {
		t.Fatalf("error = %q, want invalid_token", body["error"])
	}
}
