package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/gowk"
)

// deviceAuthorizationRequest 是 /oauth2/device_authorization 的请求体。
// 复用 OAuth2TokenRequest 的字段语义：client 凭据既可在 Basic 头也可在表单。
type deviceAuthorizationRequest struct {
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	Scope        string `form:"scope"`
	Resource     string `form:"resource"`
}

// DeviceAuthorization 处理 RFC 8628 §3.1 的 device_authorization 请求。
// 调用方是没有浏览器、没有回调地址的客户端，凭 client_id（public）或
// client_secret（confidential）认证，返回 device_code / user_code 及确认页地址。
func (o *OAuth2Handler) DeviceAuthorization(ctx *gin.Context) {
	var params deviceAuthorizationRequest
	if err := ctx.ShouldBind(&params); err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// 机密客户端可走 client_secret_basic；与 form 同时出现时以 Basic 为准。
	if clientID, clientSecret, ok := parseBasicAuth(ctx.GetHeader("Authorization")); ok {
		params.ClientID = clientID
		params.ClientSecret = clientSecret
	}

	// client 认证 + scope 校验，复用 authorize 一侧的逻辑。
	client, err := o.oauth2Service.AuthenticateDeviceClient(ctx, params.ClientID, params.ClientSecret, params.Scope)
	if err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidClient, http.StatusUnauthorized)
		return
	}

	resp, err := o.oauth2Service.DeviceAuthorization(ctx, client.ID, params.Scope, params.Resource)
	if err != nil {
		writeOAuthError(ctx, err, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}

	ctx.Header("Cache-Control", "no-store")
	ctx.JSON(http.StatusOK, resp)
}

// PollDeviceToken 处理 RFC 8628 §3.4 的轮询请求。CLI 在用户点「允许」后
// 反复调用这里，直到状态翻成 approved；此时继续走 token 端点的 device_code grant。
func (o *OAuth2Handler) PollDeviceToken(ctx *gin.Context) {
	deviceCode := ctx.PostForm("device_code")
	if strings.TrimSpace(deviceCode) == "" {
		writeOAuthError(ctx, nil, service.OAuthErrInvalidRequest, http.StatusBadRequest)
		return
	}

	approved, err := o.oauth2Service.PollDeviceToken(ctx, deviceCode)
	if err != nil {
		writeOAuthError(ctx, err, oauthErrorCode(err), oauthErrorStatus(err))
		return
	}
	if !approved {
		writeOAuthError(ctx, nil, service.OAuthErrAuthorizationPending, http.StatusBadRequest)
		return
	}

	ctx.Header("Cache-Control", "no-store")
	ctx.JSON(http.StatusOK, gin.H{"status": "approved"})
}

// DeviceConfirmPage 是确认页（GET /device?user_code=...）。
// 只在请求仍 pending 且未过期时渲染确认页；其余情况一律同一句失效文案，
// 不区分「已用/已拒/过期/不存在」，避免泄露「谁在请求什么」。
func (o *OAuth2Handler) DeviceConfirmPage(ctx *gin.Context) {
	userCode := ctx.Query("user_code")

	status, rec := o.oauth2Service.LookupPendingDeviceUserCode(ctx, userCode)
	if status != service.DevicePending || rec == nil {
		renderDeviceExpired(ctx)
		return
	}

	// 取客户端名用于展示。查不到（理论上不会，client 有外键）退回占位名。
	clientName := rec.ClientID
	if client, err := o.oauth2Service.ClientName(ctx, rec.ClientID); err == nil && client != "" {
		clientName = client
	}

	renderDeviceConfirm(ctx, deviceConfirmData{
		UserCode:   rec.UserCode,
		ClientName: clientName,
		Scope:      rec.Scope.String,
		ActionPath: ctx.Request.URL.Path,
	})
}

// DeviceConfirmDecision 处理确认页的提交：允许/拒绝，原子消费。
func (o *OAuth2Handler) DeviceConfirmDecision(ctx *gin.Context) {
	userCode := ctx.PostForm("user_code")
	decision := ctx.PostForm("decision")

	if userID := gowk.LoginId(ctx); userID <= 0 {
		renderDeviceExpired(ctx)
		return
	} else {
		switch decision {
		case "allow":
			ok, _ := o.oauth2Service.ApproveDeviceAuthorization(ctx, userCode, userID)
			if !ok {
				renderDeviceExpired(ctx)
				return
			}
			renderDeviceApproved(ctx)
		case "deny":
			ok, _ := o.oauth2Service.DenyDeviceAuthorization(ctx, userCode)
			if !ok {
				renderDeviceExpired(ctx)
				return
			}
			renderDeviceDenied(ctx)
		default:
			renderDeviceExpired(ctx)
		}
	}
}

// oauthErrorCode / oauthErrorStatus 从 error 里提取协议错误码与状态码。
// 非 *OAuthError 一律按 invalid_request 400 处理。
func oauthErrorCode(err error) string {
	if oe, ok := err.(*service.OAuthError); ok {
		return oe.Code
	}
	return service.OAuthErrInvalidRequest
}

func oauthErrorStatus(err error) int {
	if oe, ok := err.(*service.OAuthError); ok {
		return oe.Status
	}
	return http.StatusBadRequest
}

// deviceConfirmData 是确认页模板的数据。
type deviceConfirmData struct {
	UserCode   string
	ClientName string
	Scope      string
	ActionPath string
}

// renderDeviceConfirm 渲染待确认页。
func renderDeviceConfirm(ctx *gin.Context, data deviceConfirmData) {
	setBrowserPageHeaders(ctx)
	if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "device.html", data); err != nil {
		ctx.Error(err)
	}
}

// renderDeviceExpired 渲染失效页：对外唯一文案，不泄露任何状态。
func renderDeviceExpired(ctx *gin.Context) {
	setBrowserPageHeaders(ctx)
	if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "device_expired.html", nil); err != nil {
		ctx.Error(err)
	}
}

// renderDeviceApproved 渲染「已授权」成功页。
func renderDeviceApproved(ctx *gin.Context) {
	setBrowserPageHeaders(ctx)
	if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "device_approved.html", nil); err != nil {
		ctx.Error(err)
	}
}

// renderDeviceDenied 渲染「已拒绝」页。
func renderDeviceDenied(ctx *gin.Context) {
	setBrowserPageHeaders(ctx)
	if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "device_denied.html", nil); err != nil {
		ctx.Error(err)
	}
}
