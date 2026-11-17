package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/constant"
	"github.com/iautre/gowk"
)

// OAuth2TokenMiddleware 校验 Bearer access token，并把 token 与 user_id 写入上下文。
// 失败响应遵循 RFC 6750 §3，接入方库依赖 WWW-Authenticate 判断失败类型。
func OAuth2TokenMiddleware(ctx *gin.Context) {
	token, ok := strings.CutPrefix(ctx.GetHeader("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		writeBearerError(ctx, "invalid_request", "missing or malformed Authorization header")
		return
	}

	var oauth2Service service.OAuth2Service
	oauth2Token, err := oauth2Service.ValidateAccessToken(ctx, token)
	if err != nil {
		writeBearerError(ctx, "invalid_token", "access token is invalid or expired")
		return
	}

	constant.StoreContextOAuth2Token(ctx, oauth2Token)
	ctx.Next()
}

// AdminMiddleware checks if the user has admin privileges
func AdminMiddleware(ctx *gin.Context) {
	userIDInterface, exists := ctx.Get(constant.ContextUserID)
	if !exists {
		userID := gowk.LoginId(ctx)
		if userID > 0 {
			userIDInterface = userID
			exists = true
			ctx.Set(constant.ContextUserID, userID)
		}
	}
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
