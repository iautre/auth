package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/iautre/gowk"
)

func TestOAuth2BrowserLoginRedirectsAnonymousUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gowk.SetTokenHandler(&testTokenStore{})

	router := gin.New()
	router.GET("/oauth2/authorize", OAuth2BrowserLogin("/login"), func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=newapi&state=test", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}
	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, "/login?return_to=") {
		t.Fatalf("Location = %q", location)
	}
	if !strings.Contains(location, "%2Foauth2%2Fauthorize") {
		t.Fatalf("Location does not preserve authorization request: %q", location)
	}
}

func TestOAuth2BrowserLoginAcceptsSessionCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &testTokenStore{}
	gowk.SetTokenHandler(store)
	store.tokens.Store("session-token", &gowk.Token{Value: "session-token", LoginId: 42})

	router := gin.New()
	router.GET("/oauth2/authorize", OAuth2BrowserLogin("/login"), func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "%d", gowk.LoginId(ctx))
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=newapi", nil)
	request.AddCookie(&http.Cookie{Name: "oidc_jwt", Value: "session-token"})
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != "42" {
		t.Fatalf("status/body = %d/%q, want 200/42", recorder.Code, recorder.Body.String())
	}
}

func TestOIDCLoginPageOnlyAcceptsAllowedReturnPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &testTokenStore{}
	gowk.SetTokenHandler(store)
	router := gin.New()
	router.GET("/api/auth/login", OIDCLoginPageFor("/oauth2/authorize"))

	validRecorder := httptest.NewRecorder()
	validRequest := httptest.NewRequest(http.MethodGet, "/api/auth/login?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Dnewapi", nil)
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
		`data-passkey-status-path="/api/auth/passkey/status"`,
		`data-passkey-credentials-path="/api/auth/passkey/credentials"`,
		`data-passkey-login-begin-path="/api/auth/passkey/login/begin"`,
		`data-passkey-register-begin-path="/api/auth/passkey/register/begin"`,
		"new AbortController()",
		"signal: attempt.controller.signal",
		"passkeyLogin.textContent = '正在取消…'",
		"passkeyLoginAttempt === attempt) window.location.replace(window.location.href)",
		"passkeyRegistrationAttempt === attempt) window.location.replace(window.location.href)",
		"if (!attempt.cancelled) {",
		"window.clearTimeout(attempt.cancelReloadID)",
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
	if strings.Contains(validRecorder.Body.String(), `href="/api/auth/account"`) {
		t.Fatal("anonymous login page exposes account management link")
	}

	store.tokens.Store("login-page-session", &gowk.Token{Value: "login-page-session", LoginId: 42})
	authenticatedRecorder := httptest.NewRecorder()
	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/auth/login?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Dnewapi", nil)
	authenticatedRequest.AddCookie(&http.Cookie{Name: "oidc_jwt", Value: "login-page-session"})
	router.ServeHTTP(authenticatedRecorder, authenticatedRequest)
	if authenticatedRecorder.Code != http.StatusFound {
		t.Fatalf("authenticated login page status = %d, want 302", authenticatedRecorder.Code)
	}
	if location := authenticatedRecorder.Header().Get("Location"); location != "/oauth2/authorize?client_id=newapi" {
		t.Fatalf("authenticated login page redirected to %q, want return_to", location)
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

func TestAccountPageRedirectsAnonymousAndRendersForSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &testTokenStore{}
	gowk.SetTokenHandler(store)

	router := gin.New()
	router.GET("/api/auth/account", OAuth2BrowserLogin("/api/auth/login"), AccountPage)

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

// 直接打开登录页（没有 return_to）时曾因空值被判非法而回 400，
// 导致浏览器访问 auth 域名根本登录不了。空值应回退到账号中心。
func TestBrowserLoginPageDefaultsEmptyReturnToAccountPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gowk.SetTokenHandler(&testTokenStore{})

	router := gin.New()
	router.GET("/api/auth/login", OIDCLoginPageFor("/oauth2/authorize"))

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/auth/login", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if body := recorder.Body.String(); !strings.Contains(body, `data-return-to="/api/auth/account"`) {
		t.Fatal("空 return_to 没有回退到账号中心")
	}
}

// 页面下的接口路径由登录页所在路由前缀推导。挂在非 /login 结尾的路径上时，
// 旧实现（TrimSuffix "/login"）会拼出 /signin/account、/signin/passkey 这种
// 并不存在的地址，页面所有接口都会 404。
func TestBrowserLoginPageDerivesPathsFromAnyRoutePath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gowk.SetTokenHandler(&testTokenStore{})

	router := gin.New()
	router.GET("/signin", BrowserLoginPage(BrowserLoginPageOptions{}))

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/signin", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		`data-return-to="/account"`,
		`data-passkey-status-path="/passkey/status"`,
		`data-passkey-credentials-path="/passkey/credentials"`,
		`data-passkey-login-begin-path="/passkey/login/begin"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("自定义登录路径未推导出 %q", want)
		}
	}
	for _, forbidden := range []string{"/signin/account", "/signin/passkey"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("仍然拼出了不存在的路径 %q", forbidden)
		}
	}
}

// 未显式传 AuthorizationPaths 时，默认白名单必须是根路径的 /oauth2/authorize；
// 旧实现拼成 {prefix}/oauth2/auth，与任何实际路由都对不上。
func TestBrowserLoginPageFallsBackToStandardAuthorizationPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gowk.SetTokenHandler(&testTokenStore{})

	router := gin.New()
	router.GET("/api/auth/login", BrowserLoginPage(BrowserLoginPageOptions{}))

	accepted := httptest.NewRecorder()
	router.ServeHTTP(accepted, httptest.NewRequest(http.MethodGet,
		"/api/auth/login?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Dnewapi", nil))
	if accepted.Code != http.StatusOK {
		t.Fatalf("默认白名单拒绝了 /oauth2/authorize，status = %d", accepted.Code)
	}

	rejected := httptest.NewRecorder()
	router.ServeHTTP(rejected, httptest.NewRequest(http.MethodGet,
		"/api/auth/login?return_to=%2Fapi%2Fauth%2Foauth2%2Fauth", nil))
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("旧拼法 /api/auth/oauth2/auth 应被拒，status = %d", rejected.Code)
	}
}

func TestValidAuthorizationReturnToRejectsUnsafeValues(t *testing.T) {
	for _, raw := range []string{
		"",
		"/evil",
		"https://evil.example/",
		"//evil.example/",
		"/oauth2/authorize#fragment",
	} {
		if validAuthorizationReturnTo(raw, "/oauth2/authorize") {
			t.Fatalf("%q 不应通过校验", raw)
		}
	}
	if !validAuthorizationReturnTo("/oauth2/authorize?client_id=1", "/oauth2/authorize") {
		t.Fatal("带 query 的授权地址应通过校验")
	}
}
