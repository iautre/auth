// Package authhttp exposes auth's complete HTTP surface as a reusable Gin module.
// The standalone auth binary and applications embedding auth in their own HTTP server
// both call Mount, so route registration cannot drift between the two modes.
package authhttp

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/handler"
	"github.com/iautre/auth/internal/mcpserver"
	"github.com/iautre/auth/internal/route"
	"github.com/iautre/auth/migrations"
	"github.com/iautre/gowk"
)

// Options controls where the auth HTTP module is exposed.
type Options struct {
	// Prefix is prepended to auth REST endpoints. Empty exposes them at the root.
	Prefix string
	// MCPPath mounts the auth MCP endpoint on the same engine. Empty disables MCP.
	MCPPath string
}

// Module contains the mounted route group and middleware that host applications can
// reuse on their own business routes.
type Module struct {
	Group      *gin.RouterGroup
	CheckLogin gin.HandlerFunc
	CheckAdmin gin.HandlerFunc
}

// Mount injects all auth HTTP routes into router.
// Auth migrations are registered automatically; database/Redis connections and process lifecycle
// remain the host application's responsibility.
func Mount(router *gin.Engine, options Options) *Module {
	migrations.Register()

	group := router.Group(normalizePath(options.Prefix))
	ctx := context.Background()

	userHandler := handler.NewUserHandler(ctx)
	group.POST("/login", userHandler.Login)

	mqttHandler := handler.NewMqttHandler(ctx)
	group.POST("/mqtt/auth", mqttHandler.Auth)

	route.Router(group)

	if options.MCPPath != "" {
		gowk.SetupMCP(router, normalizePath(options.MCPPath), mcpserver.NewProvider(group.BasePath()), gowk.CheckLogin)
	}

	return &Module{
		Group:      group,
		CheckLogin: gowk.CheckLogin,
		CheckAdmin: handler.AdminMiddleware,
	}
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return ""
	}
	path = "/" + strings.Trim(path, "/")
	return path
}
