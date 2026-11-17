package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/config"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

// SendCode 下发一次性验证码。无论目标账号是否存在都返回同样的结果，
// 避免通过"这个手机号能不能收到码"来枚举已注册用户。
func (h *AuthHandler) SendCode(ctx *gin.Context) {
	var params dto.SendVerificationCodeParams
	if err := ctx.ShouldBind(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	var verificationService service.VerificationService
	if err := verificationService.Send(ctx, params.Channel, params.Target, params.Purpose); err != nil {
		writeAuthError(ctx, err)
		return
	}

	gowk.Response(ctx, http.StatusOK, gin.H{"sent": true, "expiresIn": 600}, nil)
}

// LoginWithCode 短信/邮箱验证码登录，目标不存在时按 AUTH_AUTO_REGISTER 决定是否建号。
func (h *AuthHandler) LoginWithCode(ctx *gin.Context) {
	var params dto.CodeLoginParams
	if err := ctx.ShouldBind(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	var userService service.UserService
	user, err := userService.LoginWithCode(ctx, params.Channel, params.Target, params.Code, config.AutoRegister())
	if err != nil {
		writeAuthError(ctx, err)
		return
	}

	recordLogin(ctx, user.ID)
	respondLogin(ctx, user)
}

// RegisterWithCode 用邮箱/手机验证码注册，成功后直接登录。
// 与验证码登录不同：目标已被占用时明确返回 400，不做"静默登录"。
func (h *AuthHandler) RegisterWithCode(ctx *gin.Context) {
	var params dto.CodeRegisterParams
	if err := ctx.ShouldBind(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	var userService service.UserService
	user, err := userService.RegisterWithCode(ctx, params.Channel, params.Target, params.Code)
	if err != nil {
		writeAuthError(ctx, err)
		return
	}

	recordLogin(ctx, user.ID)
	respondLogin(ctx, user)
}
