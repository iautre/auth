package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/iautre/gowk"
)

func TestOAuth2BrowserLoginRedirectsAnonymousUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gowk.SetTokenHandler(&testTokenStore{})

	router := gin.New()
	router.GET("/oauth2/auth", OAuth2BrowserLogin(""), func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/auth?client_id=newapi&state=test", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}
	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, "/login?return_to=") {
		t.Fatalf("Location = %q", location)
	}
	if !strings.Contains(location, "%2Foauth2%2Fauth") {
		t.Fatalf("Location does not preserve authorization request: %q", location)
	}
}

func TestOAuth2BrowserLoginAcceptsSessionCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &testTokenStore{}
	gowk.SetTokenHandler(store)
	store.tokens.Store("session-token", &gowk.Token{Value: "session-token", LoginId: 42})

	router := gin.New()
	router.GET("/oauth2/auth", OAuth2BrowserLogin(""), func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "%d", gowk.LoginId(ctx))
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/auth?client_id=newapi", nil)
	request.AddCookie(&http.Cookie{Name: "oidc_jwt", Value: "session-token"})
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != "42" {
		t.Fatalf("status/body = %d/%q, want 200/42", recorder.Code, recorder.Body.String())
	}
}

func TestOIDCLoginPageOnlyAcceptsAllowedReturnPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/auth/login", OIDCLoginPage)

	validRecorder := httptest.NewRecorder()
	validRequest := httptest.NewRequest(http.MethodGet, "/api/auth/login?return_to=%2Fapi%2Fauth%2Foauth2%2Fauth%3Fclient_id%3Dnewapi", nil)
	router.ServeHTTP(validRecorder, validRequest)
	if validRecorder.Code != http.StatusOK {
		t.Fatalf("valid status = %d, want 200", validRecorder.Code)
	}
	if !strings.Contains(validRecorder.Body.String(), "登录并继续") {
		t.Fatal("embedded login page was not rendered")
	}
	for _, want := range []string{
		"使用通行密钥",
		"取消验证",
		"取消创建",
		`href="/api/auth/account"`,
		`data-passkey-status-path="/api/auth/passkey/status"`,
		`data-passkey-credentials-path="/api/auth/passkey/credentials"`,
		`data-passkey-login-begin-path="/api/auth/passkey/login/begin"`,
		`data-passkey-register-begin-path="/api/auth/passkey/register/begin"`,
		"new AbortController()",
		"signal: attempt.controller.signal",
		`device_info: deviceInfo`,
		`id="passkey-name-dialog"`,
		"保存并继续",
		"method: 'PATCH'",
		"120000",
	} {
		if !strings.Contains(validRecorder.Body.String(), want) {
			t.Fatalf("embedded login page is missing %q", want)
		}
	}
	for _, forbidden := range []string{"window.prompt", "window.confirm", "window.alert"} {
		if strings.Contains(validRecorder.Body.String(), forbidden) {
			t.Fatalf("login page still uses native browser dialog %q", forbidden)
		}
	}

	accountRecorder := httptest.NewRecorder()
	accountRequest := httptest.NewRequest(http.MethodGet, "/api/auth/login?return_to=%2Fapi%2Fauth%2Faccount", nil)
	router.ServeHTTP(accountRecorder, accountRequest)
	if accountRecorder.Code != http.StatusOK {
		t.Fatalf("account return_to status = %d, want 200", accountRecorder.Code)
	}

	invalidRecorder := httptest.NewRecorder()
	invalidRequest := httptest.NewRequest(http.MethodGet, "/api/auth/login?return_to=https%3A%2F%2Fevil.example%2F", nil)
	router.ServeHTTP(invalidRecorder, invalidRequest)
	if invalidRecorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400", invalidRecorder.Code)
	}
}

func TestBrowserLoginPageForRemoteSDKUsesRelativeReturnTargetAndTokenStorage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/console/auth/login", BrowserLoginPage(BrowserLoginPageOptions{
		DefaultReturnTo:       "/",
		AllowRelativeReturnTo: true,
		TokenStorageKey:       "token",
	}))

	for _, target := range []string{"/", "/dashboard/workplace?tab=sms"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/console/auth/login?return_to="+url.QueryEscape(target), nil)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("target %q status = %d, want 200", target, recorder.Code)
		}
		for _, want := range []string{`data-token-storage-key="token"`, `data-passkey-enabled="false"`, "persistLoginToken(loginResult)"} {
			if !strings.Contains(recorder.Body.String(), want) {
				t.Fatalf("remote login page is missing %q", want)
			}
		}
	}

	for _, target := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example/", "/dashboard#fragment"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/console/auth/login?return_to="+url.QueryEscape(target), nil)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("target %q status = %d, want 400", target, recorder.Code)
		}
	}
}

func TestAccountPageRedirectsAnonymousAndRendersForSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &testTokenStore{}
	gowk.SetTokenHandler(store)

	router := gin.New()
	router.GET("/api/auth/account", OAuth2BrowserLogin("/api/auth"), AccountPage)

	anonymousRecorder := httptest.NewRecorder()
	anonymousRequest := httptest.NewRequest(http.MethodGet, "/api/auth/account", nil)
	router.ServeHTTP(anonymousRecorder, anonymousRequest)
	if anonymousRecorder.Code != http.StatusFound {
		t.Fatalf("anonymous status = %d, want 302", anonymousRecorder.Code)
	}
	if location := anonymousRecorder.Header().Get("Location"); location != "/api/auth/login?return_to=%2Fapi%2Fauth%2Faccount" {
		t.Fatalf("anonymous Location = %q", location)
	}

	store.tokens.Store("account-session", &gowk.Token{Value: "account-session", LoginId: 42})
	authenticatedRecorder := httptest.NewRecorder()
	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/auth/account", nil)
	authenticatedRequest.AddCookie(&http.Cookie{Name: "oidc_jwt", Value: "account-session"})
	router.ServeHTTP(authenticatedRecorder, authenticatedRequest)
	if authenticatedRecorder.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want 200", authenticatedRecorder.Code)
	}
	for _, want := range []string{
		"个人中心",
		"添加通行密钥",
		"绑定 OTP",
		"退出登录",
		"编辑资料",
		`id="action-dialog"`,
		`name="phone" type="tel" inputmode="tel" autocomplete="tel" required readonly`,
		`data-profile-path="/api/auth/user/profile"`,
		`data-otp-credentials-path="/api/auth/otp/credentials"`,
		`data-user-info-path="/api/auth/user/info"`,
		`data-passkey-credentials-path="/api/auth/passkey/credentials"`,
		"navigator.credentials.create",
		"重命名",
		`device_info: deviceInfo`,
		"method: 'PATCH'",
		"new AbortController()",
		"signal: attempt.controller.signal",
		"取消创建",
		"120000",
		"method: 'DELETE'",
		"@media (max-width: 860px)",
		"@media (max-width: 600px)",
	} {
		if !strings.Contains(authenticatedRecorder.Body.String(), want) {
			t.Fatalf("account page is missing %q", want)
		}
	}
	for _, forbidden := range []string{"window.prompt", "window.confirm", "window.alert"} {
		if strings.Contains(authenticatedRecorder.Body.String(), forbidden) {
			t.Fatalf("account page still uses native browser dialog %q", forbidden)
		}
	}
}
