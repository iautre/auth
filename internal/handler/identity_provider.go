package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

// IdentityProviderHandler 是第三方登录方式的管理接口（仅管理员）。
type IdentityProviderHandler struct{}

func NewIdentityProviderHandler() *IdentityProviderHandler { return &IdentityProviderHandler{} }

// List 返回全部配置，密钥只回"是否已配置"。
func (h *IdentityProviderHandler) List(ctx *gin.Context) {
	var providerService service.IdentityProviderService
	list, err := providerService.List(ctx)
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, list, nil)
}

// Create 新增第三方登录方式。
func (h *IdentityProviderHandler) Create(ctx *gin.Context) {
	var params dto.IdentityProviderParams
	if err := ctx.ShouldBind(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	var providerService service.IdentityProviderService
	created, err := providerService.Create(ctx, &params)
	if err != nil {
		writeProviderError(ctx, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, created, nil)
}

// Update 修改第三方登录方式；client_secret 留空表示保持原值。
func (h *IdentityProviderHandler) Update(ctx *gin.Context) {
	id, ok := parseProviderID(ctx)
	if !ok {
		return
	}

	var params dto.IdentityProviderParams
	if err := ctx.ShouldBind(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}

	var providerService service.IdentityProviderService
	updated, err := providerService.Update(ctx, id, &params)
	if err != nil {
		writeProviderError(ctx, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, updated, nil)
}

// Delete 删除第三方登录方式。仍有用户绑定时会被拒绝。
func (h *IdentityProviderHandler) Delete(ctx *gin.Context) {
	id, ok := parseProviderID(ctx)
	if !ok {
		return
	}

	var providerService service.IdentityProviderService
	if err := providerService.Delete(ctx, id); err != nil {
		writeProviderError(ctx, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, gin.H{"deleted": true}, nil)
}

func parseProviderID(ctx *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		gowk.Response(ctx, http.StatusBadRequest, nil, errors.New("无效的 provider id"))
		return 0, false
	}
	return id, true
}

func writeProviderError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrProviderNameInvalid),
		errors.Is(err, service.ErrProviderIssuerBad),
		errors.Is(err, service.ErrProviderSecretNeeded):
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
	case errors.Is(err, service.ErrFederatedProviderNotFound):
		gowk.Response(ctx, http.StatusNotFound, nil, err)
	case errors.Is(err, service.ErrProviderInUse):
		gowk.Response(ctx, http.StatusConflict, nil, err)
	default:
		gowk.Response(ctx, http.StatusInternalServerError, nil, err)
	}
}
