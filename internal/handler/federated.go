package handler

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

// FederatedHandler 处理第三方 OIDC 登录（auth 作为 RP）。
type FederatedHandler struct {
	// loginURL 是失败时要退回的登录页；为空表示宿主没有页面，直接回 JSON 错误。
	loginURL string
}

func NewFederatedHandler(loginURL string) *FederatedHandler {
	return &FederatedHandler{loginURL: loginURL}
}

// Providers 返回可用于登录的第三方列表，公开接口，供登录页渲染按钮。
func (h *FederatedHandler) Providers(ctx *gin.Context) {
	var federatedService service.FederatedService
	list, err := federatedService.PublicProviders(ctx)
	if err != nil {
		writeAuthError(ctx, err)
		return
	}
	if list == nil {
		list = []dto.PublicIdentityProvider{}
	}
	gowk.Response(ctx, http.StatusOK, list, nil)
}

// BeginLogin 跳转到第三方授权端点。
// return_to 由调用方带过来：独立部署时是原本要去的 /oauth2/authorize?...，
// 嵌入时是宿主前端自己的路径。
func (h *FederatedHandler) BeginLogin(ctx *gin.Context) {
	name := ctx.Param("provider")

	var federatedService service.FederatedService
	authURL, err := federatedService.BeginLogin(ctx, name, ctx.Query("return_to"))
	if err != nil {
		h.fail(ctx, err)
		return
	}
	ctx.Redirect(http.StatusFound, authURL)
}

// Callback 处理第三方回调：换 token、验签、登录，然后跳回 return_to。
func (h *FederatedHandler) Callback(ctx *gin.Context) {
	name := ctx.Param("provider")

	if providerErr := ctx.Query("error"); providerErr != "" {
		description := ctx.Query("error_description")
		if description == "" {
			description = providerErr
		}
		h.fail(ctx, service.ErrFederatedStateInvalid, description)
		return
	}

	var federatedService service.FederatedService
	user, returnTo, err := federatedService.CompleteLogin(ctx, name, ctx.Query("code"), ctx.Query("state"))
	if err != nil {
		h.fail(ctx, err)
		return
	}

	token, err := gowk.Login(ctx, user.ID)
	if err != nil {
		h.fail(ctx, err)
		return
	}

	recordLogin(ctx, user.ID)

	if returnTo != "" {
		ctx.Redirect(http.StatusFound, returnTo)
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

// fail 有登录页就带错误跳回去，没有就回 JSON。
func (h *FederatedHandler) fail(ctx *gin.Context, err error, override ...string) {
	message := err.Error()
	if len(override) > 0 && override[0] != "" {
		message = override[0]
	}

	if h.loginURL == "" {
		writeAuthError(ctx, err)
		return
	}

	target := h.loginURL + "?error=" + url.QueryEscape(message)
	ctx.Redirect(http.StatusFound, target)
}
