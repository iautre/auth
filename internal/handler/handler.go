package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/constant"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

type UserHandler struct {
}

func NewUserHandler(ctx context.Context) *UserHandler {
	return &UserHandler{}
}

func (u *UserHandler) Login(ctx *gin.Context) {
	var params dto.LoginParams
	if err := ctx.ShouldBind(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	var userService service.UserService
	user, err := userService.Login(ctx, &params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// 独立部署与包内嵌模式统一签发 gowk native token；OIDC ID Token 仅由 OAuth2/OIDC 流程签发。
	token, err := gowk.Login(ctx, user.ID)
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, dto.LoginRes{
		Token:      token,
		UserId:     user.ID,
		Nickname:   user.Nickname.String,
		Avatar:     user.Avatar.String,
		IsVerified: user.IsVerified.Bool,
	}, nil)
}

func (u *UserHandler) UserInfo(ctx *gin.Context) {
	userId := gowk.LoginId(ctx)
	var userService service.UserService
	user, err := userService.GetById(ctx, userId)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, userResponse(user), nil)
}

// ResetOTPCode generates new OTP secret for user (admin only)
func (u *UserHandler) ResetOTPCode(ctx *gin.Context) {
	userId, err := strconv.ParseInt(ctx.Param("userId"), 10, 64)
	if err != nil || userId <= 0 {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("invalid user ID"))
		return
	}
	var userService service.UserService
	newSecret, err := userService.ResetOTPCode(ctx, userId)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, map[string]interface{}{
		"userId":    userId,
		"newSecret": newSecret,
		"message":   "OTP code reset successfully",
	}, nil)
}

type OAuth2Handler struct {
	oauth2Service *service.OAuth2Service
	oidcService   *service.OIDCService
}

func NewOAuth2Handler(ctx context.Context) *OAuth2Handler {
	return &OAuth2Handler{
		oauth2Service: service.NewOAuth2Service(ctx),
		oidcService:   service.DefaultOIDCService(),
	}
}

// OAuth2Auth 处理授权请求（GET）。校验通过后先看是否已就该 client 授过权，
// 没有则渲染授权确认页，避免已登录状态下被任意第三方客户端静默取走身份。
func (o *OAuth2Handler) OAuth2Auth(ctx *gin.Context) {
	params, client, ok := o.authorizeRequest(ctx, func(p *dto.OAuth2AuthRequest) error {
		return ctx.ShouldBindQuery(p)
	})
	if !ok {
		return
	}

	if !hasConsent(ctx, params.ClientID) {
		renderConsentPage(ctx, params, client)
		return
	}

	o.issueAuthorizationCode(ctx, params)
}

// OAuth2AuthDecision 处理授权确认页的提交：允许则登记同意并发码，拒绝则带
// access_denied 回跳。表单走 POST 且依赖会话 cookie，跨站提交不会携带该
// cookie（浏览器默认 SameSite=Lax），因此无需额外 CSRF 令牌。
func (o *OAuth2Handler) OAuth2AuthDecision(ctx *gin.Context) {
	params, _, ok := o.authorizeRequest(ctx, func(p *dto.OAuth2AuthRequest) error {
		return ctx.ShouldBind(p)
	})
	if !ok {
		return
	}

	switch ctx.PostForm("decision") {
	case "allow":
		grantConsent(ctx, params.ClientID)
		o.issueAuthorizationCode(ctx, params)
	case "deny":
		redirectOAuthErrorFrom(ctx, params.RedirectURI, params.State, &service.OAuthError{
			Code:        service.OAuthErrAccessDenied,
			Description: "user denied the authorization request",
			Status:      http.StatusBadRequest,
		})
	default:
		writeOAuthError(ctx, errors.New("decision must be allow or deny"),
			service.OAuthErrInvalidRequest, http.StatusBadRequest)
	}
}

// authorizeRequest 完成授权请求的公共校验，失败时已经写好响应。
// bind 由调用方提供，因为 GET 读查询串、POST 读表单。
func (o *OAuth2Handler) authorizeRequest(ctx *gin.Context, bind func(*dto.OAuth2AuthRequest) error) (*dto.OAuth2AuthRequest, *service.AuthorizedClient, bool) {
	var params dto.OAuth2AuthRequest
	if err := bind(&params); err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return nil, nil, false
	}

	// 未登录时既不查库也不重定向：宿主未提供登录页（LoginURL 为空）时，
	// 由这里返回标准的未认证响应，而不是把用户导向任何地址。
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		writeOAuthError(ctx, &service.OAuthError{
			Code:        "login_required",
			Description: "user is not authenticated",
			Status:      http.StatusUnauthorized,
		}, service.OAuthErrInvalidRequest, http.StatusUnauthorized)
		return nil, nil, false
	}

	// 第二步判断"能否把用户送回这个客户端"。这一步失败时 redirect_uri 本身
	// 不可信，按 RFC 6749 §4.1.2.1 不得重定向，必须就地报错。
	client, err := o.oauth2Service.ValidateClientRedirect(ctx, params.ClientID, params.RedirectURI)
	if err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return nil, nil, false
	}

	// 客户端可能不带 scope：按它自己登记的 scope 补齐，避免按参数错误拒绝委托。
	if strings.TrimSpace(params.Scope) == "" {
		params.Scope = client.DefaultScope()
	}

	// redirect_uri 自此可信，后续参数错误改为带 error 重定向回去，
	// 让接入方能拿到具体原因而不是一个无法解析的错误页。
	if err := o.oauth2Service.ValidateAuthRequest(client, &params); err != nil {
		redirectOAuthErrorFrom(ctx, params.RedirectURI, params.State, err)
		return nil, nil, false
	}

	return &params, client, true
}

// issueAuthorizationCode 签发授权码并把浏览器送回客户端的 redirect_uri。
func (o *OAuth2Handler) issueAuthorizationCode(ctx *gin.Context, params *dto.OAuth2AuthRequest) {
	userID := gowk.LoginId(ctx)

	authCode, err := o.oauth2Service.GenerateAuthorizationCode(
		ctx,
		params.ClientID,
		userID,
		params.RedirectURI,
		params.Scope,
		params.State,
		params.Nonce,
		params.CodeChallenge,
		params.CodeChallengeMethod,
	)
	if err != nil {
		redirectOAuthErrorFrom(ctx, params.RedirectURI, params.State, err)
		return
	}

	// Build redirect URL
	redirectURL, err := url.Parse(params.RedirectURI)
	if err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}

	queryParams := redirectURL.Query()
	queryParams.Set("code", authCode)
	if params.State != "" {
		queryParams.Set("state", params.State)
	}
	redirectURL.RawQuery = queryParams.Encode()

	ctx.Redirect(http.StatusFound, redirectURL.String())
}

// writeOAuthError 按 RFC 6749 §5.2 直接返回错误体。
// OAuthError 原样输出 code 与 status（例如客户端认证失败必须是 401 invalid_client）；
// 其余错误按调用方指定的兜底 code 输出。
func writeOAuthError(ctx *gin.Context, err error, fallbackCode string, fallbackStatus int) {
	code, description, status := oauthErrorDetail(err, fallbackCode, fallbackStatus)
	ctx.Header("Cache-Control", "no-store")
	ctx.JSON(status, gin.H{"error": code, "error_description": description})
	ctx.Abort()
}

// redirectOAuthError 把错误带回客户端已登记的 redirect_uri。
func redirectOAuthError(ctx *gin.Context, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             service.OAuthErrInvalidRequest,
			"error_description": "redirect_uri is malformed",
		})
		ctx.Abort()
		return
	}
	query := u.Query()
	query.Set("error", code)
	if description != "" {
		query.Set("error_description", description)
	}
	if state != "" {
		query.Set("state", state)
	}
	u.RawQuery = query.Encode()
	ctx.Redirect(http.StatusFound, u.String())
}

func redirectOAuthErrorFrom(ctx *gin.Context, redirectURI, state string, err error) {
	code, description, _ := oauthErrorDetail(err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
	redirectOAuthError(ctx, redirectURI, state, code, description)
}

func oauthErrorDetail(err error, fallbackCode string, fallbackStatus int) (code, description string, status int) {
	var oauthErr *service.OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr.Code, oauthErr.Description, oauthErr.Status
	}
	return fallbackCode, err.Error(), fallbackStatus
}

// writeBearerError 按 RFC 6750 §3 返回带 WWW-Authenticate 的 401。
func writeBearerError(ctx *gin.Context, code, description string) {
	ctx.Header("WWW-Authenticate", `Bearer error="`+code+`", error_description="`+description+`"`)
	ctx.Header("Cache-Control", "no-store")
	ctx.JSON(http.StatusUnauthorized, gin.H{"error": code, "error_description": description})
	ctx.Abort()
}

// OIDCToken 返回 RFC 6749/OIDC 客户端预期的顶层 token 字段。
func (o *OAuth2Handler) OIDCToken(ctx *gin.Context) {
	// token 响应携带凭据，禁止任何中间层缓存（RFC 6749 §5.1）。
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")

	var params dto.OAuth2TokenRequest
	if err := ctx.ShouldBind(&params); err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// 机密客户端可用 client_secret_basic 提交凭据；与 form 参数同时出现时以 Basic 为准。
	if clientID, clientSecret, ok := parseBasicAuth(ctx.GetHeader("Authorization")); ok {
		params.ClientID = clientID
		params.ClientSecret = clientSecret
	}

	response, err := o.oauth2Service.ExchangeToken(ctx, &params)
	if err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidGrant, http.StatusBadRequest)
		return
	}
	ctx.JSON(http.StatusOK, response)
	ctx.Abort()
}

// parseBasicAuth 解析 client_secret_basic（RFC 6749 §2.3.1）。
//
// 凭据在放入 Basic 头之前经过 application/x-www-form-urlencoded 编码，这里还原后再比对；
// 按第一个冒号切分，允许 secret 内含冒号。头缺失或格式不合法时返回 ok=false，
// 调用方回落到 form 参数。
func parseBasicAuth(header string) (clientID, clientSecret string, ok bool) {
	after, found := strings.CutPrefix(header, "Basic ")
	if !found {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(after)
	if err != nil {
		return "", "", false
	}
	name, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	if clientID, err = url.QueryUnescape(name); err != nil {
		return "", "", false
	}
	if clientSecret, err = url.QueryUnescape(pass); err != nil {
		return "", "", false
	}
	return clientID, clientSecret, true
}

func (o *OAuth2Handler) OIDCDiscovery(ctx *gin.Context) {
	// Discovery 只包含公开的 OIDC 元数据，允许浏览器端客户端跨域自动发现。
	// Token / UserInfo 等携带凭据的端点不开放 CORS。
	ctx.Header("Access-Control-Allow-Origin", "*")
	discovery := o.oidcService.GetDiscoveryDocument()
	ctx.JSON(http.StatusOK, discovery)
	ctx.Abort()
}

func (o *OAuth2Handler) OIDCUserInfo(ctx *gin.Context) {
	// 与 OAuth2TokenMiddleware 写入键保持一致；裸字符串 "user_id" 容易跟 constant 漂移，
	// 一旦键改名静默拿不到 userID 就会全场 401，统一走常量。
	userIDInterface, exists := ctx.Get(constant.ContextUserID)
	if !exists {
		writeBearerError(ctx, "invalid_token", "access token is not associated with a user")
		return
	}

	userID, ok := userIDInterface.(int64)
	if !ok || userID <= 0 {
		writeBearerError(ctx, "invalid_token", "access token is not associated with a user")
		return
	}

	// userinfo 属于 OIDC 端点，要求 access token 至少带 openid scope。
	scope := grantedOAuth2Scope(ctx)
	if !scopeContains(scope, "openid") {
		ctx.Header("WWW-Authenticate", `Bearer error="insufficient_scope", error_description="openid scope is required"`)
		ctx.JSON(http.StatusForbidden, gin.H{"error": "insufficient_scope", "error_description": "openid scope is required"})
		ctx.Abort()
		return
	}

	userInfo, err := o.oidcService.UserInfoForScope(ctx, userID, scope)
	if err != nil {
		writeBearerError(ctx, "invalid_token", "user no longer available")
		return
	}
	ctx.Header("Cache-Control", "no-store")
	ctx.JSON(http.StatusOK, userInfo)
	ctx.Abort()
}

func scopeContains(scope, want string) bool {
	for _, granted := range strings.Fields(scope) {
		if granted == want {
			return true
		}
	}
	return false
}

// grantedOAuth2Scope 取出 OAuth2TokenMiddleware 写入的 token scope，
// 供 userinfo 按授予范围裁剪返回字段。
func grantedOAuth2Scope(ctx *gin.Context) string {
	token, ok := constant.LoadContextOAuth2Token(ctx)
	if !ok || token == nil {
		return ""
	}
	return token.Scope.String
}

func (o *OAuth2Handler) OIDCJwks(ctx *gin.Context) {
	jwks, err := o.oidcService.GetJwks(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporarily_unavailable", "error_description": err.Error()})
		ctx.Abort()
		return
	}
	ctx.JSON(http.StatusOK, jwks)
	ctx.Abort()
}

// nativeToken mirrors gowk.Token JSON structure for Redis deserialization.
type nativeToken struct {
	Value     string `json:"value"`
	LoginId   int64  `json:"loginId"`
	Device    string `json:"device"`
	Timeout   int64  `json:"timeout"`
	CreatedAt int64  `json:"createdAt"`
}

const redisTokenPrefix = "ATOKEN_TOKEN_"

// OAuth2ClientHandler handles OAuth2 client management HTTP requests
type OAuth2ClientHandler struct {
	clientService *service.OAuth2ClientService
}

// NewOAuth2ClientHandler creates a new OAuth2ClientHandler
func NewOAuth2ClientHandler(ctx context.Context) *OAuth2ClientHandler {
	return &OAuth2ClientHandler{
		clientService: service.NewOAuth2ClientService(ctx),
	}
}

// CreateOAuth2Client creates a new OAuth2 client
func (h *OAuth2ClientHandler) CreateOAuth2Client(ctx *gin.Context) {
	var params dto.OAuth2ClientCreateParams
	if err := ctx.ShouldBindJSON(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	client, err := h.clientService.CreateOAuth2Client(ctx, &params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// gowk.Response 只把 200 视为成功，其它状态码会把 data 丢掉；而这里返回的
	// secret 只回显一次，丢了就再也拿不回来，因此固定用 200。
	gowk.Response(ctx, http.StatusOK, client, nil)
}

// UpdateOAuth2Client updates an existing OAuth2 client
func (h *OAuth2ClientHandler) UpdateOAuth2Client(ctx *gin.Context) {
	clientID := ctx.Param("id")
	if clientID == "" {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("client ID is required"))
		return
	}

	var params dto.OAuth2ClientUpdateParams
	if err := ctx.ShouldBindJSON(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// Set client ID from URL parameter
	params.ID = clientID

	client, err := h.clientService.UpdateOAuth2Client(ctx, &params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, client, nil)
}

// GetOAuth2Client retrieves an OAuth2 client by ID
func (h *OAuth2ClientHandler) GetOAuth2Client(ctx *gin.Context) {
	clientID := ctx.Param("id")
	if clientID == "" {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("client ID is required"))
		return
	}

	client, err := h.clientService.GetOAuth2Client(ctx, clientID)
	if err != nil {
		gowk.Response(ctx, http.StatusNotFound, nil, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, client, nil)
}

// ListOAuth2Clients lists all OAuth2 clients
func (h *OAuth2ClientHandler) ListOAuth2Clients(ctx *gin.Context) {

	response, err := h.clientService.ListOAuth2Clients(ctx)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, response, nil)
}

// DeleteOAuth2Client soft deletes an OAuth2 client
func (h *OAuth2ClientHandler) DisableOAuth2Client(ctx *gin.Context) {
	clientID := ctx.Param("id")
	if clientID == "" {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("client ID is required"))
		return
	}

	err := h.clientService.DisableOAuth2Client(ctx, clientID)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, gin.H{
		"client_id": clientID,
		"message":   "OAuth2 client disabled successfully",
	}, nil)
}

// RegenerateClientSecret generates a new secret for an OAuth2 client
func (h *OAuth2ClientHandler) RegenerateClientSecret(ctx *gin.Context) {
	clientID := ctx.Param("id")
	if clientID == "" {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("client ID is required"))
		return
	}
	newSecret := gowk.GenerateRandomString(64)
	if _, err := h.clientService.RegenerateClientSecret(ctx, clientID, newSecret); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, map[string]interface{}{
		"client_id":  clientID,
		"new_secret": newSecret,
		"message":    "Client secret regenerated successfully",
		"warning":    "Please save this secret securely, it will not be shown again",
	}, nil)
}
