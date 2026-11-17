package authhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/pkg/authhttp"
)

func routeSet(router *gin.Engine) map[string]bool {
	set := make(map[string]bool)
	for _, r := range router.Routes() {
		set[r.Method+" "+r.Path] = true
	}
	return set
}

func TestSetupMountsAPIWithPagesAndProtocolRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	module := authhttp.Setup(router, authhttp.SetupOptions{
		APIPrefix: "/api/auth",
		OAuth:     true,
		Pages:     true,
	})
	if module == nil || module.UserAuth == nil {
		t.Fatal("Setup 没有返回带 UserAuth 的 Module")
	}

	routes := routeSet(router)
	for _, want := range []string{
		"POST /api/auth/login",
		"GET /api/auth/login",
		"GET /api/auth/account",
		"GET /oauth2/authorize",
		"POST /oauth2/token",
		"GET /oidc/userinfo",
		"GET /oidc/jwks",
		"GET /.well-known/openid-configuration",
	} {
		if !routes[want] {
			t.Errorf("缺少路由 %s", want)
		}
	}
}

func TestSetupWithoutPagesOrOAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	authhttp.Setup(router, authhttp.SetupOptions{APIPrefix: "/api/auth"})

	routes := routeSet(router)
	if !routes["POST /api/auth/login"] {
		t.Error("业务 API 的登录接口应始终挂载")
	}
	for _, unwanted := range []string{
		"GET /api/auth/login",
		"GET /api/auth/account",
		"GET /oauth2/authorize",
		"GET /.well-known/openid-configuration",
	} {
		if routes[unwanted] {
			t.Errorf("关闭 Pages/OAuth 后不应注册 %s", unwanted)
		}
	}
}

// UserAuth 在没有登录态时必须直接 401，不能放行到业务 handler。
func TestUserAuthRejectsAnonymousRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	module := authhttp.MountAPI(router, authhttp.APIOptions{})
	router.GET("/private", module.UserAuth, func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "reached")
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/private", nil))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if body := recorder.Body.String(); body == "reached" {
		t.Fatal("未认证请求进入了业务 handler")
	}
}
