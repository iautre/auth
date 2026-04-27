package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/constant"
	"github.com/iautre/gowk"
)

// OAuth2 token validation middleware
func OAuth2TokenMiddleware(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("Missing Authorization header"))
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("Invalid Authorization header format"))
		return
	}

	// Use OAuth2Service to validate token
	var oauth2Service service.OAuth2Service
	oauth2Token, err := oauth2Service.ValidateAccessToken(ctx, token)
	if err != nil {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("Invalid or expired access token"))
		return
	}

	// Store token info in context
	constant.StoreContextOAuth2Token(ctx, oauth2Token)
	ctx.Next()
}

// AdminMiddleware checks if the user has admin privileges
func AdminMiddleware(ctx *gin.Context) {
	userIDInterface, exists := ctx.Get(constant.ContextUserID)
	if !exists {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("User not authenticated"))
		return
	}

	userID, ok := userIDInterface.(int64)
	if !ok {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("Invalid user ID"))
		return
	}

	var userService service.UserService
	user, err := userService.GetById(ctx, userID)
	if err != nil {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("User not found"))
		return
	}

	// 不区分大小写：历史数据可能写入 lower-case，避免误拦截。
	if !strings.EqualFold(user.Group.String, constant.USER_GROUP_ADMIN) {
		gowk.Response(ctx, http.StatusForbidden, nil, gowk.NewError("Admin access required"))
		return
	}

	constant.StoreContextAdmin(ctx, true)
	ctx.Next()
}
