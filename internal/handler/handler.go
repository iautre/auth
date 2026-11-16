package handler

import (
	"context"
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

func (u *UserHandler) BasicAuthMiddleware(ctx *gin.Context) {
	err := u.validateBasicAuth(ctx)
	if err != nil {
		u.requireBasicAuth(ctx)
		return
	}
	// 验证通过（实际场景）
	ctx.Next()
}

func (u *UserHandler) requireBasicAuth(ctx *gin.Context) {
	// Set WWW-Authenticate header (required)
	ctx.Header("WWW-Authenticate", `Basic realm="Authentication required"`)
	// Return 401 Unauthorized status code (required)
	gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("Authentication required"))
}

func (u *UserHandler) validateBasicAuth(ctx *gin.Context) error {
	auth := ctx.GetString(gowk.ContextBasicAuthKey)
	if auth == "" {
		return nil
	}
	// Split username and password
	parts := strings.SplitN(auth, ":", 2)
	if len(parts) != 2 {
		return gowk.NewError("invalid credentials format")
	}

	username := parts[0]
	password := parts[1]

	// Validate username and password
	if username == "" || password == "" {
		return gowk.NewError("username and password cannot be empty")
	}
	params := &dto.LoginParams{
		Account: username,
		Code:    password,
	}
	// Query user from database and validate credentials
	var userService service.UserService
	user, err := userService.Login(ctx, params)
	if err != nil {
		return err // Return the actual error from Login method
	}
	_, err = gowk.Login(ctx, user.ID)
	if err != nil {
		return err
	}
	return nil
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

// SSOLogin 暂未实现，明确返回 501 以避免下游误以为可用。
func (u *UserHandler) SSOLogin(ctx *gin.Context) {
	var params dto.SSOLoginRequest
	if err := ctx.ShouldBind(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	var ssoService service.SSOService
	response, err := ssoService.LoginWithProvider(ctx, &params)
	if err != nil {
		if errors.Is(err, service.ErrSSONotImplemented) {
			gowk.Response(ctx, http.StatusNotImplemented, nil, err)
			return
		}
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, response, nil)
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

func (o *OAuth2Handler) OAuth2Auth(ctx *gin.Context) {
	// Parse request parameters
	var params dto.OAuth2AuthRequest
	if err := ctx.ShouldBindQuery(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// 取登录用户 ID。前置中间件 gowk.CheckLogin / BasicAuthMiddleware 已经把
	// 已认证用户写入 ContextLoginIdKey；但当这些中间件存在某些"静默放行"路径时，
	// LoginId 可能是 0。无主授权码会让攻击者用 sub=0 换 token，必须在此再设一道闸：
	// 没有有效用户身份直接 401，由前端跳转到登录页。
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("login required"))
		return
	}

	// Validate request using existing service layer
	_, err := o.oauth2Service.ValidateOAuth2AuthRequest(ctx, &params)
	if err != nil {
		gowk.Response(ctx, http.StatusUnauthorized, nil, err)
		return
	}

	// Generate authorization code using existing service
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
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// Build redirect URL
	redirectURL, err := url.Parse(params.RedirectURI)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
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

func (o *OAuth2Handler) OAuth2Token(ctx *gin.Context) {
	var params dto.OAuth2TokenRequest
	err := ctx.ShouldBind(&params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// Use unified ExchangeToken method
	response, err := o.oauth2Service.ExchangeToken(ctx, &params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, response, nil)
}

// OIDCToken 返回 RFC 6749/OIDC 客户端预期的顶层 token 字段。
func (o *OAuth2Handler) OIDCToken(ctx *gin.Context) {
	var params dto.OAuth2TokenRequest
	if err := ctx.ShouldBind(&params); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		ctx.Abort()
		return
	}

	response, err := o.oauth2Service.ExchangeToken(ctx, &params)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		ctx.Abort()
		return
	}
	ctx.JSON(http.StatusOK, response)
	ctx.Abort()
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
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("User ID not found in context"))
		return
	}

	userID, ok := userIDInterface.(int64)
	if !ok {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("Invalid user ID"))
		return
	}

	userInfo, err := o.oidcService.GetUserInfo(ctx, userID)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	ctx.JSON(http.StatusOK, userInfo)
	ctx.Abort()
}

func (o *OAuth2Handler) OIDCJwks(ctx *gin.Context) {
	jwks := o.oidcService.GetJwks(ctx.Request.Context())
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

	gowk.Response(ctx, http.StatusCreated, client, nil)
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
