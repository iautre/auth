package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

type PasskeyHandler struct{}

type passkeyFinishRequest struct {
	FlowToken  string                    `json:"flow_token" binding:"required"`
	Credential json.RawMessage           `json:"credential" binding:"required"`
	DeviceInfo service.PasskeyDeviceInfo `json:"device_info"`
}

type passkeyNameRequest struct {
	Name string `json:"name" binding:"required"`
}

func NewPasskeyHandler() *PasskeyHandler {
	return &PasskeyHandler{}
}

func (p *PasskeyHandler) Status(ctx *gin.Context) {
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("login required"))
		return
	}
	var passkeys service.PasskeyService
	enabled, err := passkeys.Status(ctx, userID)
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, map[string]bool{"has_passkey": enabled}, nil)
}

func (p *PasskeyHandler) Credentials(ctx *gin.Context) {
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("login required"))
		return
	}
	var passkeys service.PasskeyService
	credentials, err := passkeys.ListCredentials(ctx, userID)
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, gowk.NewError("failed to list passkey credentials"))
		return
	}
	gowk.Response(ctx, http.StatusOK, credentials, nil)
}

func (p *PasskeyHandler) DeleteCredential(ctx *gin.Context) {
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("login required"))
		return
	}
	credentialID, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil || credentialID <= 0 {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("invalid passkey credential"))
		return
	}
	var passkeys service.PasskeyService
	deleted, err := passkeys.DeleteCredential(ctx, userID, credentialID)
	if errors.Is(err, service.ErrLastAuthenticationMethod) {
		gowk.Response(ctx, http.StatusConflict, nil, service.ErrLastAuthenticationMethod)
		return
	}
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, gowk.NewError("failed to delete passkey credential"))
		return
	}
	if !deleted {
		gowk.Response(ctx, http.StatusNotFound, nil, gowk.NewError("passkey credential not found"))
		return
	}
	gowk.Response(ctx, http.StatusOK, map[string]string{"message": "passkey deleted"}, nil)
}

func (p *PasskeyHandler) UpdateCredentialName(ctx *gin.Context) {
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("login required"))
		return
	}
	credentialID, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil || credentialID <= 0 {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("无效的通行密钥"))
		return
	}
	var request passkeyNameRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("请填写通行密钥名称"))
		return
	}
	name := strings.TrimSpace(request.Name)
	if name == "" {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("请填写通行密钥名称"))
		return
	}
	if len([]rune(name)) > 50 {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("通行密钥名称不能超过 50 个字符"))
		return
	}
	var passkeys service.PasskeyService
	credential, updated, err := passkeys.UpdateCredentialName(ctx, userID, credentialID, name)
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, gowk.NewError("更新通行密钥名称失败"))
		return
	}
	if !updated {
		gowk.Response(ctx, http.StatusNotFound, nil, gowk.NewError("通行密钥不存在"))
		return
	}
	gowk.Response(ctx, http.StatusOK, credential, nil)
}

func (p *PasskeyHandler) RegisterBegin(ctx *gin.Context) {
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("login required"))
		return
	}
	var passkeys service.PasskeyService
	result, err := passkeys.BeginRegistration(ctx, userID)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, result, nil)
}

func (p *PasskeyHandler) RegisterFinish(ctx *gin.Context) {
	userID := gowk.LoginId(ctx)
	if userID <= 0 {
		gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("login required"))
		return
	}
	request, ok := bindPasskeyFinish(ctx)
	if !ok {
		return
	}
	var passkeys service.PasskeyService
	credential, err := passkeys.FinishRegistration(ctx, userID, request.FlowToken, request.Credential, request.DeviceInfo)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, credential, nil)
}

func (p *PasskeyHandler) LoginBegin(ctx *gin.Context) {
	var passkeys service.PasskeyService
	result, err := passkeys.BeginLogin(ctx)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, result, nil)
}

func (p *PasskeyHandler) LoginFinish(ctx *gin.Context) {
	request, ok := bindPasskeyFinish(ctx)
	if !ok {
		return
	}
	var passkeys service.PasskeyService
	user, err := passkeys.FinishLogin(ctx, request.FlowToken, request.Credential)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
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

func bindPasskeyFinish(ctx *gin.Context) (*passkeyFinishRequest, bool) {
	var request passkeyFinishRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return nil, false
	}
	return &request, true
}

func BrowserSameOrigin(ctx *gin.Context) {
	if err := service.ValidateBrowserOrigin(ctx.GetHeader("Origin")); err != nil {
		gowk.Response(ctx, http.StatusForbidden, nil, gowk.NewError("request origin is not allowed"))
		return
	}
	ctx.Next()
}
