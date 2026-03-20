package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	authpb "github.com/iautre/auth/pkg/proto"
	"github.com/iautre/gowk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
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

	// 签发 JWT（RS256），其他服务凭 JWKS 公钥本地验证，无需 Redis 或 gRPC
	var oidcService service.OIDCService
	jwtToken, err := oidcService.GenerateIDToken(ctx, user.ID, "auth", "")
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, jwtToken, nil)
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

	// Create user response with additional fields
	userRes := dto.UserRes{
		Id:          user.ID,
		Phone:       user.Phone.String,
		Email:       user.Email.String,
		Nickname:    user.Nickname.String,
		Group:       user.Group.String,
		Avatar:      user.Avatar.String,
		IsVerified:  user.IsVerified.Bool,
		Enabled:     user.Enabled,
		LastLoginAt: user.LastLoginAt.Time.Format("2006-01-02T15:04:05Z"),
		Created:     user.Created.Time.Format("2006-01-02T15:04:05Z"),
	}

	gowk.Response(ctx, http.StatusOK, userRes, nil)
}

// SSO Login endpoint
func (u *UserHandler) SSOLogin(ctx *gin.Context) {
	var params dto.SSOLoginRequest
	err := ctx.ShouldBind(&params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// Gin binding validation already handles all validation rules via binding tags
	var ssoService service.SSOService
	response, err := ssoService.LoginWithProvider(ctx, &params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, response, nil)
}

// ResetOTPCode generates new OTP secret for user (admin only)
func (u *UserHandler) ResetOTPCode(ctx *gin.Context) {
	userId := gowk.LoginId(ctx)
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
		oidcService:   &service.OIDCService{},
	}
}

func (o *OAuth2Handler) OAuth2Auth(ctx *gin.Context) {
	// Parse request parameters
	var params dto.OAuth2AuthRequest
	if err := ctx.ShouldBindQuery(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// Get user ID from session or token
	userID := gowk.LoginId(ctx)

	// Validate request using existing service layer
	_, err := o.oauth2Service.ValidateOAuth2AuthRequest(ctx, &params)
	if err != nil {
		gowk.Response(ctx, http.StatusUnauthorized, nil, err)
		return
	}

	// Generate authorization code using existing service
	authCode, err := o.oauth2Service.GenerateAuthorizationCode(ctx, params.ClientID, userID, params.RedirectURI, params.Scope, params.State, params.Nonce)
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

func (o *OAuth2Handler) OIDCDiscovery(ctx *gin.Context) {
	discovery := o.oidcService.GetDiscoveryDocument()
	gowk.Response(ctx, http.StatusOK, discovery, nil)
}

func (o *OAuth2Handler) OIDCUserInfo(ctx *gin.Context) {
	// Get user ID from OAuth2TokenMiddleware
	userIDInterface, exists := ctx.Get("user_id")
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
	gowk.Response(ctx, http.StatusOK, userInfo, nil)
}

func (o *OAuth2Handler) OIDCJwks(ctx *gin.Context) {
	jwks := o.oidcService.GetJwks()
	gowk.Response(ctx, http.StatusOK, jwks, nil)
}

// GrpcHandler 处理gRPC相关的请求
type GrpcHandler struct {
	oauth2Service *service.OAuth2Service
	oidcService   *service.OIDCService
}

func NewGrpcHandler(ctx context.Context) *GrpcHandler {
	return &GrpcHandler{
		oauth2Service: service.NewOAuth2Service(ctx),
		oidcService:   &service.OIDCService{},
	}
}

// OAuth2Token handles OAuth2 token endpoint - gRPC version
func (g *GrpcHandler) OAuth2Token(ctx context.Context, req *authpb.OAuth2TokenRequest) (*authpb.OAuth2TokenResponse, error) {
	// Convert gRPC request to internal format
	tokenReq := &dto.OAuth2TokenRequest{
		GrantType:    req.GrantType,
		Code:         req.Code,
		RedirectURI:  req.RedirectUri,
		ClientID:     req.ClientId,
		ClientSecret: req.ClientSecret,
		RefreshToken: req.RefreshToken,
		Scope:        req.Scope,
		CodeVerifier: req.CodeVerifier,
	}

	// Use unified ExchangeToken method
	response, err := g.oauth2Service.ExchangeToken(ctx, tokenReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "token exchange failed: %v", err)
	}

	// Convert to gRPC response format
	return &authpb.OAuth2TokenResponse{
		AccessToken:  response.AccessToken,
		TokenType:    response.TokenType,
		ExpiresIn:    response.ExpiresIn,
		RefreshToken: response.RefreshToken,
		Scope:        response.Scope,
		IdToken:      response.IDToken,
	}, nil
}

// OIDCUserInfo handles OIDC userinfo endpoint - gRPC version
func (g *GrpcHandler) OIDCUserInfo(ctx context.Context, req *authpb.OIDCUserInfoRequest) (*authpb.OIDCUserInfoResponse, error) {
	// Use OAuth2Service to validate access token
	oauth2Token, err := g.oauth2Service.ValidateAccessToken(ctx, req.AccessToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired access token: %v", err)
	}

	// Use existing OIDCService to get user info
	userInfo, err := g.oidcService.GetUserInfo(ctx, oauth2Token.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get user info: %v", err)
	}

	// Convert to gRPC response format
	return &authpb.OIDCUserInfoResponse{
		Sub:                 userInfo.Sub,
		Name:                userInfo.Name,
		Email:               userInfo.Email,
		EmailVerified:       userInfo.EmailVerified,
		GivenName:           userInfo.GivenName,
		FamilyName:          userInfo.FamilyName,
		MiddleName:          userInfo.MiddleName,
		Nickname:            userInfo.Nickname,
		PreferredUsername:   userInfo.PreferredUsername,
		Picture:             userInfo.Picture,
		PhoneNumber:         userInfo.PhoneNumber,
		PhoneNumberVerified: userInfo.PhoneVerified,
		Locale:              userInfo.Locale,
		UpdatedAt:           userInfo.UpdatedAt,
	}, nil
}

// OIDCDiscovery handles OIDC discovery endpoint - gRPC version
func (g *GrpcHandler) OIDCDiscovery(ctx context.Context, req *emptypb.Empty) (*authpb.OIDCDiscoveryResponse, error) {
	// Use existing OIDCService
	discovery := g.oidcService.GetDiscoveryDocument()

	// Convert to gRPC response format
	return &authpb.OIDCDiscoveryResponse{
		Issuer:                           discovery.Issuer,
		AuthorizationEndpoint:            discovery.AuthorizationEndpoint,
		TokenEndpoint:                    discovery.TokenEndpoint,
		UserinfoEndpoint:                 discovery.UserInfoEndpoint,
		JwksUri:                          discovery.JwksUri,
		ScopesSupported:                  discovery.ScopesSupported,
		ResponseTypesSupported:           discovery.ResponseTypesSupported,
		GrantTypesSupported:              discovery.GrantTypesSupported,
		SubjectTypesSupported:            discovery.SubjectTypesSupported,
		IdTokenSigningAlgValuesSupported: discovery.IDTokenSigningAlgValuesSupported,
	}, nil
}

// OIDCJwks handles OIDC JWKS endpoint - gRPC version
func (g *GrpcHandler) OIDCJwks(ctx context.Context, req *emptypb.Empty) (*authpb.OIDCJwksResponse, error) {
	// Use existing OIDCService
	jwks := g.oidcService.GetJwks()

	// Convert to gRPC response format
	var keys []*authpb.OIDCJwk
	for _, key := range jwks.Keys {
		keys = append(keys, &authpb.OIDCJwk{
			Kty: key.Kty,
			Use: key.Use,
			Kid: key.Kid,
			N:   key.N,
			E:   key.E,
			Alg: key.Alg,
		})
	}

	return &authpb.OIDCJwksResponse{
		Keys: keys,
	}, nil
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

// CheckToken 从 Redis 验证 auth 服务签发的 native token，返回用户 ID。
// 其他服务通过 gRPC 调用此接口，无需直连 Redis 即可完成 token 鉴权。
func (g *GrpcHandler) CheckToken(ctx context.Context, req *authpb.CheckTokenRequest) (*authpb.CheckTokenResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	jsonData, err := gowk.Redis().Get(ctx, redisTokenPrefix+req.Token).Result()
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid or expired token")
	}

	var t nativeToken
	if err := json.Unmarshal([]byte(jsonData), &t); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse token")
	}

	if t.Timeout > 0 && t.CreatedAt > 0 {
		if time.Now().Unix() > t.CreatedAt+t.Timeout {
			return nil, status.Error(codes.Unauthenticated, "token expired")
		}
	}

	return &authpb.CheckTokenResponse{
		UserId: t.LoginId,
		Device: t.Device,
	}, nil
}

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

	// Generate new secret
	newSecret := gowk.GenerateRandomString(64)

	// Update client with new secrets
	params := &dto.OAuth2ClientUpdateParams{
		ID:     clientID,
		Secret: newSecret,
	}

	_, err := h.clientService.UpdateOAuth2Client(ctx, params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	// Return only the new secret (not the full client info)
	gowk.Response(ctx, http.StatusOK, map[string]interface{}{
		"client_id":  clientID,
		"new_secret": newSecret,
		"message":    "Client secret regenerated successfully",
		"warning":    "Please save this secret securely, it will not be shown again",
	}, nil)
}
