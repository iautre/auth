package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CredentialEndpointCORS 允许浏览器端 MCP 客户端跨域访问携带凭据的端点。
//
// 这些端点靠 Authorization 头或 client 认证，不读 cookie，因此回 * 而不是
// 回显 Origin：回显 Origin 只对凭据模式（credentials: include）有意义，
// 而这里刻意不支持带 cookie 的跨域调用。
func CredentialEndpointCORS(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")
	ctx.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
	ctx.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	ctx.Header("Access-Control-Max-Age", "600")

	// 预检请求不带凭据，直接回 204，不进入后续鉴权中间件。
	if ctx.Request.Method == http.MethodOptions {
		ctx.AbortWithStatus(http.StatusNoContent)
		return
	}
}
