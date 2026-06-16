package mcpserver

import (
	"github.com/iautre/gowk"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewProvider 构建 auth MCP provider。
// tool 直接调用 internal/service（与 HTTP handler 同一份逻辑），不走 HTTP 回连；
// 鉴权由挂载时的中间件负责（见 cmd/server.go：与受登录保护的 HTTP 接口同一道 gowk.CheckLogin）。
func NewProvider() *Server { return &Server{} }

// Server 仅负责把 auth 业务 service 注册为 MCP tool。
type Server struct{}

func (s *Server) MCPName() string    { return "auth" }
func (s *Server) MCPVersion() string { return gowk.Version }

func (s *Server) RegisterMCPTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "auth_oidc_discovery",
		Description: "获取 OIDC Discovery 文档",
	}, s.oidcDiscovery)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "auth_oidc_jwks",
		Description: "获取 OIDC JWKS 公钥",
	}, s.oidcJwks)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "auth_user_info",
		Description: "获取当前登录用户信息（身份取自 /mcp 鉴权中间件）",
	}, s.userInfo)
}
