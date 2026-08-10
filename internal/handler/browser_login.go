package handler

import (
	"bufio"
	"embed"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/gowk"
)

//go:embed templates/*.html
var browserPageFS embed.FS

var browserPageTemplate = template.Must(template.ParseFS(browserPageFS, "templates/*.html"))

type loginPageData struct {
	LoginPath                 string
	PasskeyStatusPath         string
	PasskeyCredentialsPath    string
	PasskeyRegisterBeginPath  string
	PasskeyRegisterFinishPath string
	PasskeyLoginBeginPath     string
	PasskeyLoginFinishPath    string
	AccountPath               string
	ReturnTo                  string
	PasskeyEnabled            bool
	ShowAccountLink           bool
}

type accountPageData struct {
	LoginPath                 string
	UserInfoPath              string
	ProfilePath               string
	LogoutPath                string
	OTPCredentialsPath        string
	OTPEnrollmentBeginPath    string
	OTPEnrollmentFinishPath   string
	PasskeyCredentialsPath    string
	PasskeyRegisterBeginPath  string
	PasskeyRegisterFinishPath string
}

// BrowserLoginPageOptions controls Auth's standalone browser login page.
type BrowserLoginPageOptions struct {
	AuthorizationPaths []string
	EnablePasskey      bool
	ShowAccountLink    bool
}

// BrowserLoginPage renders Auth's standalone browser login page.
func BrowserLoginPage(options BrowserLoginPageOptions) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		loginPath := ctx.Request.URL.Path
		returnTo := ctx.Query("return_to")
		accountPath := strings.TrimSuffix(loginPath, "/login") + "/account"
		authorizationPaths := options.AuthorizationPaths
		if len(authorizationPaths) == 0 {
			authorizationPaths = []string{authorizationPath(loginPath)}
		}
		allowedReturnPaths := append(append([]string{}, authorizationPaths...), accountPath)
		validReturnTo := validAuthorizationReturnTo(returnTo, allowedReturnPaths...)
		if !validReturnTo {
			ctx.String(http.StatusBadRequest, "invalid return_to")
			return
		}

		setBrowserPageHeaders(ctx)
		passkeyPath := strings.TrimSuffix(loginPath, "/login") + "/passkey"
		if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "login.html", loginPageData{
			LoginPath:                 loginPath,
			PasskeyStatusPath:         passkeyPath + "/status",
			PasskeyCredentialsPath:    passkeyPath + "/credentials",
			PasskeyRegisterBeginPath:  passkeyPath + "/register/begin",
			PasskeyRegisterFinishPath: passkeyPath + "/register/finish",
			PasskeyLoginBeginPath:     passkeyPath + "/login/begin",
			PasskeyLoginFinishPath:    passkeyPath + "/login/finish",
			AccountPath:               accountPath,
			ReturnTo:                  returnTo,
			PasskeyEnabled:            options.EnablePasskey,
			ShowAccountLink:           options.ShowAccountLink,
		}); err != nil {
			ctx.Error(err)
		}
	}
}

func OIDCLoginPage(ctx *gin.Context) {
	OIDCLoginPageFor()(ctx)
}

// OIDCLoginPageFor builds Auth's standalone login page and allows it to return
// only to the supplied authorization endpoints (plus the local account page).
func OIDCLoginPageFor(authorizationPaths ...string) gin.HandlerFunc {
	return BrowserLoginPage(BrowserLoginPageOptions{
		AuthorizationPaths: authorizationPaths,
		EnablePasskey:      true,
		ShowAccountLink:    true,
	})
}

func AccountPage(ctx *gin.Context) {
	accountPath := ctx.Request.URL.Path
	basePath := strings.TrimSuffix(accountPath, "/account")
	passkeyPath := basePath + "/passkey"

	setBrowserPageHeaders(ctx)
	if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "account.html", accountPageData{
		LoginPath:                 basePath + "/login",
		UserInfoPath:              basePath + "/user/info",
		ProfilePath:               basePath + "/user/profile",
		LogoutPath:                basePath + "/logout",
		OTPCredentialsPath:        basePath + "/otp/credentials",
		OTPEnrollmentBeginPath:    basePath + "/otp/enrollment/begin",
		OTPEnrollmentFinishPath:   basePath + "/otp/enrollment/finish",
		PasskeyCredentialsPath:    passkeyPath + "/credentials",
		PasskeyRegisterBeginPath:  passkeyPath + "/register/begin",
		PasskeyRegisterFinishPath: passkeyPath + "/register/finish",
	}); err != nil {
		ctx.Error(err)
	}
}

func setBrowserPageHeaders(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	ctx.Header("X-Content-Type-Options", "nosniff")
	ctx.Header("Referrer-Policy", "no-referrer")
	ctx.Header("Content-Type", "text/html; charset=utf-8")
}

func OAuth2BrowserLogin(loginURL string) gin.HandlerFunc {
	loginURL = strings.TrimSpace(loginURL)
	return func(ctx *gin.Context) {
		probe := ctx.Copy()
		probe.Writer = newProbeResponseWriter()
		gowk.CheckLogin(probe)

		if userID := gowk.LoginId(probe); userID > 0 {
			ctx.Set(gowk.ContextLoginIdKey, userID)
			if token := gowk.TokenInfo(probe); token != nil {
				ctx.Set(gowk.ContextTokenKey, token)
			}
			if tokenValue := gowk.TokenValue(probe); tokenValue != "" {
				ctx.Set(gowk.ContextTokenValueKey, tokenValue)
			}
			ctx.Next()
			return
		}
		if loginURL == "" {
			// Continue into OAuth2Auth, which returns the standard unauthenticated
			// response. The reusable package does not own browser navigation.
			ctx.Next()
			return
		}

		query := url.Values{}
		query.Set("return_to", ctx.Request.URL.RequestURI())
		ctx.Redirect(http.StatusFound, loginURL+"?"+query.Encode())
		ctx.Abort()
	}
}

func authorizationPath(loginPath string) string {
	return strings.TrimSuffix(loginPath, "/login") + "/oauth2/auth"
}

func validAuthorizationReturnTo(raw string, expectedPaths ...string) bool {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return false
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
		return false
	}
	for _, expectedPath := range expectedPaths {
		if parsed.Path == expectedPath {
			return true
		}
	}
	return false
}

type probeResponseWriter struct {
	header http.Header
	status int
	size   int
}

func newProbeResponseWriter() *probeResponseWriter {
	return &probeResponseWriter{header: make(http.Header), status: http.StatusOK, size: -1}
}

func (w *probeResponseWriter) Header() http.Header { return w.header }

func (w *probeResponseWriter) WriteHeader(statusCode int) {
	if !w.Written() {
		w.status = statusCode
		w.size = 0
	}
}

func (w *probeResponseWriter) Write(data []byte) (int, error) {
	if !w.Written() {
		w.WriteHeader(http.StatusOK)
	}
	w.size += len(data)
	return len(data), nil
}

func (w *probeResponseWriter) WriteString(value string) (int, error) {
	return w.Write([]byte(value))
}

func (w *probeResponseWriter) Status() int         { return w.status }
func (w *probeResponseWriter) Size() int           { return w.size }
func (w *probeResponseWriter) Written() bool       { return w.size >= 0 }
func (w *probeResponseWriter) WriteHeaderNow()     { w.WriteHeader(w.status) }
func (w *probeResponseWriter) Flush()              {}
func (w *probeResponseWriter) Pusher() http.Pusher { return nil }

func (w *probeResponseWriter) CloseNotify() <-chan bool {
	closed := make(chan bool)
	return closed
}

func (w *probeResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("response writer does not support hijacking")
}
