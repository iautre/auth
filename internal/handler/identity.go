package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

// IdentityHandler 是当前用户查看/解绑自己第三方账号的接口。
type IdentityHandler struct{}

func NewIdentityHandler() *IdentityHandler { return &IdentityHandler{} }

// List 返回当前用户已绑定的第三方身份。
func (h *IdentityHandler) List(ctx *gin.Context) {
	var identityService service.IdentityService
	rows, err := identityService.List(ctx, gowk.LoginId(ctx))
	if err != nil {
		gowk.Response(ctx, http.StatusInternalServerError, nil, err)
		return
	}

	out := make([]dto.IdentityBindingRes, 0, len(rows))
	for _, row := range rows {
		binding := dto.IdentityBindingRes{
			Provider:    row.Provider,
			DisplayName: row.DisplayName.String,
			Email:       row.Email.String,
			Avatar:      row.Avatar.String,
		}
		if row.Created.Valid {
			binding.Created = row.Created.Time.Format(time.RFC3339)
		}
		out = append(out, binding)
	}
	gowk.Response(ctx, http.StatusOK, out, nil)
}

// Unlink 解绑一个第三方身份；解绑后必须还剩至少一种登录方式。
func (h *IdentityHandler) Unlink(ctx *gin.Context) {
	var identityService service.IdentityService
	err := identityService.Unlink(ctx, gowk.LoginId(ctx), ctx.Param("provider"))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrIdentityNotFound):
			gowk.Response(ctx, http.StatusNotFound, nil, err)
		case errors.Is(err, service.ErrLastAuthenticationMethod):
			gowk.Response(ctx, http.StatusBadRequest, nil, err)
		default:
			gowk.Response(ctx, http.StatusInternalServerError, nil, err)
		}
		return
	}
	gowk.Response(ctx, http.StatusOK, gin.H{"unlinked": true}, nil)
}
