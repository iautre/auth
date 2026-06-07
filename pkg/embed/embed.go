// Package embed 提供将 auth 以「远程（gRPC）」方式嵌入其他系统的 gin 中间件与登录路由。
//
// 本包是 client-only：仅依赖 auth 的 pkg/client、pkg/proto、pkg/dto 与 gowk，
// 不引用任何 internal 包，因此可被其他服务通过 go get 远程依赖，
// 无需 auth 的 internal/db 等服务端生成代码。
//
// 通过环境变量 AUTH_GRPC_ADDR 指向远程 auth gRPC 服务（如 auth:50051）。
// 早期的 local（与 auth 共享数据库、直连 internal/service）模式已移除；
// 需要 local 直连的场景应直接使用 auth 服务端自身，而非嵌入本包。
package embed

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	authclient "github.com/iautre/auth/pkg/client"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

// ─── 用户上下文 ────────────────────────────────────────────────────────────────

// ContextUserKey 是写入 gin.Context 的用户对象键。
const ContextUserKey = "AUTH_CONTEXT_USER"

// 用户分组常量
const (
	GroupAdmin   = "ADMIN"
	GroupDefault = "DEFAULT"
)

// User 是 auth 系统写入请求上下文的用户信息（只含业务必要字段）。
type User struct {
	Id       int64
	Nickname string
	Group    string
}

// IsAdmin 判断是否为管理员。
func (u *User) IsAdmin() bool { return u != nil && u.Group == GroupAdmin }

// ContextUser 从 gin.Context 中读取当前登录用户，不存在时返回 nil。
func ContextUser(ctx *gin.Context) *User {
	v, ok := ctx.Get(ContextUserKey)
	if !ok {
		return nil
	}
	u, _ := v.(*User)
	return u
}

// UserId 快捷获取当前登录用户 ID，未登录时返回 0。
func UserId(ctx *gin.Context) int64 {
	if u := ContextUser(ctx); u != nil {
		return u.Id
	}
	return 0
}

// ─── 中间件集 ──────────────────────────────────────────────────────────────────

// Middlewares 包含 Setup 返回的核心中间件。
//   - Login：验证 token，将 userId 写入 context。
//   - UserAuth：根据 userId 查询用户信息，将 *User 写入 context（key: ContextUserKey）。
//   - CheckAdmin：校验当前用户是否为管理员，非管理员返回 403。
type Middlewares struct {
	Login      gin.HandlerFunc
	UserAuth   gin.HandlerFunc
	CheckAdmin gin.HandlerFunc
	// doLogin 是登录实现，由 Setup 内部填充（远程 gRPC 登录）。
	doLogin func(ctx *gin.Context) (token string, userId int64, nickname string, err error)
}

func (m *Middlewares) loginHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, userId, nickname, err := m.doLogin(ctx)
		if err != nil {
			gowk.Fail(ctx, &gowk.ErrorCode{
				Status: http.StatusUnauthorized,
				Code:   http.StatusUnauthorized,
				Msg:    err.Error(),
			})
			return
		}
		gowk.Success(ctx, gin.H{
			"token":    token,
			"userId":   userId,
			"nickname": nickname,
		})
	}
}

// ─── Setup ────────────────────────────────────────────────────────────────────

// Setup 以远程模式挂载 auth 的 HTTP 路由与中间件，并注册登录接口 prefix + "/login"。
// 需要环境变量 AUTH_GRPC_ADDR 指向 auth gRPC 服务（如 auth:50051）。
//
// 调用方只需：
//
//	mw := embed.Setup(router, "/api/auth")
//	api := router.Group("/api", mw.Login, mw.UserAuth)
func Setup(router *gin.Engine, prefix string) *Middlewares {
	grpcAddr := os.Getenv("AUTH_GRPC_ADDR")
	if grpcAddr == "" {
		panic("auth: 远程模式必须配置 AUTH_GRPC_ADDR（如 auth:50051）")
	}
	c, err := authclient.NewAuthClient(grpcAddr, "", "")
	if err != nil {
		panic("auth: gRPC 客户端初始化失败: " + err.Error())
	}
	c.MountRemote(router, prefix)
	mw := &Middlewares{
		Login:      remoteLoginMW(c),
		UserAuth:   remoteUserAuth(c),
		CheckAdmin: checkAdmin(),
		doLogin:    remoteDoLogin(c),
	}
	router.POST(prefix+"/login", mw.loginHandler())
	return mw
}

func checkAdmin() gin.HandlerFunc {
	forbidden := &gowk.ErrorCode{Status: http.StatusForbidden, Code: http.StatusForbidden, Msg: "权限不足"}
	return func(ctx *gin.Context) {
		if u := ContextUser(ctx); u == nil || !u.IsAdmin() {
			gowk.Fail(ctx, forbidden)
			return
		}
		ctx.Next()
	}
}

func remoteDoLogin(c *authclient.AuthClient) func(*gin.Context) (string, int64, string, error) {
	return func(ctx *gin.Context) (string, int64, string, error) {
		var params dto.LoginParams
		if err := ctx.ShouldBind(&params); err != nil {
			return "", 0, "", err
		}
		resp, err := c.Login(ctx.Request.Context(), params.Account, params.Code, ctx.GetHeader("User-Agent"))
		if err != nil {
			return "", 0, "", err
		}
		return resp.Token, resp.UserId, resp.Nickname, nil
	}
}

func remoteLoginMW(c *authclient.AuthClient) gin.HandlerFunc {
	unauth := &gowk.ErrorCode{Status: http.StatusUnauthorized, Code: http.StatusUnauthorized, Msg: "认证失败"}
	return func(ctx *gin.Context) {
		token := bearerToken(ctx)
		if token == "" {
			gowk.Fail(ctx, unauth)
			return
		}
		resp, err := c.CheckToken(ctx.Request.Context(), token)
		if err != nil {
			gowk.Fail(ctx, unauth)
			return
		}
		ctx.Set(gowk.ContextLoginIdKey, resp.UserId)
		ctx.Next()
	}
}

func remoteUserAuth(c *authclient.AuthClient) gin.HandlerFunc {
	unauth := &gowk.ErrorCode{Status: http.StatusUnauthorized, Code: http.StatusUnauthorized, Msg: "认证失败"}
	return func(ctx *gin.Context) {
		id := gowk.LoginId(ctx)
		if id <= 0 {
			gowk.Fail(ctx, unauth)
			return
		}
		info, err := c.GetUserInfo(ctx.Request.Context(), id)
		if err != nil {
			gowk.Fail(ctx, unauth)
			return
		}
		ctx.Set(ContextUserKey, &User{
			Id:       info.UserId,
			Nickname: info.Nickname,
			Group:    info.Group,
		})
		ctx.Next()
	}
}

func bearerToken(ctx *gin.Context) string {
	auth := ctx.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ctx.GetHeader("X-Token")
}
