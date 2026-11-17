package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
)

// OAuth2Register 实现 RFC 7591 动态客户端注册，供 MCP 客户端自助登记。
// 只接受 public client：请求里的 token_endpoint_auth_method 必须是 none。
func (o *OAuth2Handler) OAuth2Register(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")

	var params dto.OAuth2ClientRegistrationRequest
	if err := ctx.ShouldBindJSON(&params); err != nil {
		writeOAuthError(ctx, err, service.RegistrationErrInvalidClientMetadata, http.StatusBadRequest)
		return
	}

	clientService := service.NewOAuth2ClientService(ctx)
	response, err := clientService.RegisterPublicClient(ctx, &params)
	if err != nil {
		var registrationErr *service.RegistrationError
		if errors.As(err, &registrationErr) {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":             registrationErr.Code,
				"error_description": registrationErr.Description,
			})
			ctx.Abort()
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		ctx.Abort()
		return
	}

	ctx.JSON(http.StatusCreated, response)
	ctx.Abort()
}
