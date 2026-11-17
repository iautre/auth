package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/gowk"
)

// ProtectedResourceMetadataPath 返回 MCP 资源对应的 RFC 9728 元数据路径。
// 规范要求把 /.well-known/oauth-protected-resource 插在 host 与资源路径之间，
// 例如资源 /mcp 对应 /.well-known/oauth-protected-resource/mcp。
func ProtectedResourceMetadataPath(mcpPath string) string {
	const wellKnown = "/.well-known/oauth-protected-resource"
	trimmed := strings.Trim(mcpPath, "/")
	if trimmed == "" {
		return wellKnown
	}
	return wellKnown + "/" + trimmed
}

// ResourceURL 返回资源的绝对地址，作为元数据里的 resource 字段。
func ResourceURL(mcpPath string) string {
	base := gowk.BaseURL()
	trimmed := strings.Trim(mcpPath, "/")
	if trimmed == "" {
		return base
	}
	return base + "/" + trimmed
}

// ProtectedResourceMetadata 实现 RFC 9728 §3 的保护资源元数据。
// 客户端在 /mcp 上收到 401 后按 WWW-Authenticate 里的 resource_metadata
// 找到这里，从中得知该由哪个授权服务器签发 token。
func ProtectedResourceMetadata(mcpPath string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 与 discovery 一致：只含公开元数据，允许浏览器端客户端跨域获取。
		ctx.Header("Access-Control-Allow-Origin", "*")
		ctx.Header("Cache-Control", "no-store")
		ctx.JSON(http.StatusOK, gin.H{
			"resource":                 ResourceURL(mcpPath),
			"authorization_servers":    []string{gowk.BaseURL()},
			"scopes_supported":         strings.Fields(service.DefaultAuthorizeScope),
			"bearer_methods_supported": []string{"header"},
		})
		ctx.Abort()
	}
}
