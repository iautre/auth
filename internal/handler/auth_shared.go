package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

// AuthHandler 提供无密码的登录入口：一次性验证码登录与注册。
type AuthHandler struct{}

func NewAuthHandler() *AuthHandler { return &AuthHandler{} }

// respondLogin 统一签发登录态：一次写 cookie，同时把同一个 native token 放进响应体。
// 浏览器走 cookie，前后端分离或原生客户端走 Authorization: Bearer。
func respondLogin(ctx *gin.Context, user db2.AuthUser) {
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

// writeAuthError 把 service 层的可判别错误映射成对应的 HTTP 状态。
// 未识别的错误一律 500，不把内部细节当业务提示返回。
func writeAuthError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidCredentials),
		errors.Is(err, service.ErrAccountDisabled):
		gowk.Response(ctx, http.StatusUnauthorized, nil, err)

	case errors.Is(err, service.ErrEmailTaken),
		errors.Is(err, service.ErrPhoneTaken),
		errors.Is(err, service.ErrCodeInvalid),
		errors.Is(err, service.ErrCodeExpired),
		errors.Is(err, service.ErrCodeTooManyAttempts),
		errors.Is(err, service.ErrCodeRateLimited),
		errors.Is(err, service.ErrCodeDailyLimit),
		errors.Is(err, service.ErrInvalidTarget),
		errors.Is(err, service.ErrChannelNotConfigured):
		gowk.Response(ctx, http.StatusBadRequest, nil, err)

	default:
		gowk.Response(ctx, http.StatusInternalServerError, nil, err)
	}
}

// recordLogin 更新最近登录时间与次数，失败不阻断登录。
func recordLogin(ctx *gin.Context, userID int64) {
	var userService service.UserService
	if err := userService.UpdateLoginInfo(ctx, userID); err != nil {
		slog.WarnContext(context.Background(), "update login info failed", "user_id", userID, "err", err)
	}
}
