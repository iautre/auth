package handler

import (
	"strings"

	"github.com/gin-gonic/gin"
)

type providerPageData struct {
	ListPath    string
	AccountPath string
}

// IdentityProviderPage 渲染第三方登录方式的管理页面（仅管理员可达）。
func IdentityProviderPage(ctx *gin.Context) {
	pagePath := ctx.Request.URL.Path
	basePath := strings.TrimSuffix(pagePath, "/admin/providers")

	setBrowserPageHeaders(ctx)
	if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "admin_providers.html", providerPageData{
		ListPath:    basePath + "/admin/identity-providers",
		AccountPath: basePath + "/account",
	}); err != nil {
		ctx.Error(err)
	}
}
