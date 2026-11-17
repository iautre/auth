package authhttp

import (
	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/gowk"
)

// MCPAuth 返回与 Auth 内置 MCP 端点完全相同的鉴权中间件，供宿主挂在自己的
// MCP 路由上：先认 Authorization: Bearer 里的 OAuth2 access token，再回落
// 浏览器会话，都不成立时回 401 并在 WWW-Authenticate 里给出元数据地址。
//
// resourcePath 是宿主 MCP 资源的路径（例如 "/mcp"），只用于拼元数据地址；
// 该元数据需要由 SetupOptions.ProtectedResourcePath 发布，或宿主自行提供，
// 否则客户端拿到地址也取不到内容。
func MCPAuth(resourcePath string) gin.HandlerFunc {
	return handler.MCPAuth(gowk.BaseURL() + handler.ProtectedResourceMetadataPath(resourcePath))
}
