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
	TokenStorageKey           string
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

// BrowserLoginPageOptions controls the browser login page when Auth is mounted
// by another application. TokenStorageKey is intended for remote SDK hosts:
// the token returned by their proxied login endpoint is stored under this key
// before the browser is redirected back to that same host.
type BrowserLoginPageOptions struct {
	DefaultReturnTo       string
	AllowRelativeReturnTo bool
	TokenStorageKey       string
	EnablePasskey         bool
	ShowAccountLink       bool
}

// BrowserLoginPage renders Auth's reusable browser login page.
//
// Standalone Auth and authhttp.Mount keep the stricter OAuth/account-only
// return target policy through OIDCLoginPage. Remote SDK hosts may opt into
// same-origin relative targets so the token can be returned to their own SPA.
func BrowserLoginPage(options BrowserLoginPageOptions) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		loginPath := ctx.Request.URL.Path
		returnTo := ctx.Query("return_to")
		accountPath := strings.TrimSuffix(loginPath, "/login") + "/account"
		if returnTo == "" && options.DefaultReturnTo != "" {
			returnTo = options.DefaultReturnTo
		}
		validReturnTo := validAuthorizationReturnTo(returnTo, authorizationPath(loginPath), accountPath)
		if options.AllowRelativeReturnTo {
			validReturnTo = validRelativeReturnTo(returnTo)
		}
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
			TokenStorageKey:           options.TokenStorageKey,
			PasskeyEnabled:            options.EnablePasskey,
			ShowAccountLink:           options.ShowAccountLink,
		}); err != nil {
			ctx.Error(err)
		}
	}
}

func OIDCLoginPage(ctx *gin.Context) {
	BrowserLoginPage(BrowserLoginPageOptions{
		EnablePasskey:   true,
		ShowAccountLink: true,
	})(ctx)
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

func OAuth2BrowserLogin(prefix string) gin.HandlerFunc {
	loginPath := strings.TrimSuffix(prefix, "/") + "/login"
	if loginPath == "" {
		loginPath = "/login"
	}

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

		query := url.Values{}
		query.Set("return_to", ctx.Request.URL.RequestURI())
		ctx.Redirect(http.StatusFound, loginPath+"?"+query.Encode())
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

func validRelativeReturnTo(raw string) bool {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "#\\") {
		return false
	}
	parsed, err := url.ParseRequestURI(raw)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" && parsed.Fragment == ""
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
