package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/gowk"
)

type OTPHandler struct{}

type otpEnrollmentBeginRequest struct {
	Name string `json:"name"`
}

type otpEnrollmentFinishRequest struct {
	FlowToken string `json:"flow_token" binding:"required"`
	Code      string `json:"code" binding:"required,len=6"`
}

func NewOTPHandler() *OTPHandler {
	return &OTPHandler{}
}

func (o *OTPHandler) Credentials(ctx *gin.Context) {
	var otps service.OTPService
	credentials, err := otps.ListCredentials(ctx, gowk.LoginId(ctx))
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, gowk.NewError("获取 OTP 列表失败"))
		return
	}
	gowk.Response(ctx, http.StatusOK, credentials, nil)
}

func (o *OTPHandler) EnrollmentBegin(ctx *gin.Context) {
	var request otpEnrollmentBeginRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("无效的 OTP 绑定请求"))
		return
	}
	var otps service.OTPService
	result, err := otps.BeginEnrollment(ctx, gowk.LoginId(ctx), request.Name)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, result, nil)
}

func (o *OTPHandler) EnrollmentFinish(ctx *gin.Context) {
	var request otpEnrollmentFinishRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("请输入 6 位动态验证码"))
		return
	}
	var otps service.OTPService
	if err := otps.FinishEnrollment(ctx, gowk.LoginId(ctx), request.FlowToken, request.Code); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, map[string]string{"message": "OTP bound"}, nil)
}

func (o *OTPHandler) DeleteCredential(ctx *gin.Context) {
	credentialID, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil || credentialID <= 0 {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("无效的 OTP 凭据"))
		return
	}
	var otps service.OTPService
	deleted, err := otps.DeleteCredential(ctx, gowk.LoginId(ctx), credentialID)
	if errors.Is(err, service.ErrLastAuthenticationMethod) {
		gowk.Response(ctx, http.StatusConflict, nil, service.ErrLastAuthenticationMethod)
		return
	}
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, gowk.NewError("解绑 OTP 失败"))
		return
	}
	if !deleted {
		gowk.Response(ctx, http.StatusNotFound, nil, gowk.NewError("OTP 凭据不存在"))
		return
	}
	gowk.Response(ctx, http.StatusOK, map[string]string{"message": "OTP deleted"}, nil)
}
