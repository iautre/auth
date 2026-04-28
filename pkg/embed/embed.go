// Package embed 提供将 auth 作为"可嵌入模块"接入其他系统的能力。
//   - local 模式（AUTH_MODE=local 或未设置）：挂载路由、使用同一 DB/Redis，登录与用户信息由 auth 直接提供。
//   - remote 模式（AUTH_MODE=remote）：全部路由通过 gRPC 与远端 auth 服务通信，需配置 AUTH_GRPC_ADDR。
package embed

import (
	"context"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	authclient "github.com/iautre/auth/pkg/client"
	"github.com/iautre/auth/internal/route"
	"github.com/iautre/auth/internal/service"
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
	// doLogin 是模式相关的登录实现，由 Setup 内部填充。
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

// Setup 读取环境变量 AUTH_MODE（local/remote），自动选择实现：
//   - local：在 router 上以 prefix 为前缀挂载 auth HTTP 路由，用 gowk Redis 验证 token。
//   - remote：通过 AUTH_GRPC_ADDR 与 auth gRPC 服务通信，挂载相同 HTTP 路由（后端走 gRPC）。
//
// 登录接口固定为 prefix + "/login"，所有 auth 相关路径均由 auth 统一定义。
//
// 调用方只需：
//
//	mw := auth.Setup(router, "/api/auth")
//	api := router.Group("/api", mw.Login, mw.UserAuth)
func Setup(router *gin.Engine, prefix string) *Middlewares {
	var mw *Middlewares
	if isRemote() {
		mw = setupRemote(router, prefix)
	} else {
		mw = setupLocal(router, prefix)
	}
	router.POST(prefix+"/login", mw.loginHandler())
	return mw
}

func isRemote() bool {
	return os.Getenv("AUTH_MODE") == "remote"
}

// ─── local 模式 ────────────────────────────────────────────────────────────────

func setupLocal(router *gin.Engine, prefix string) *Middlewares {
	Mount(router, prefix)
	return &Middlewares{
		Login:      gowk.CheckLoginMiddleware(),
		UserAuth:   localUserAuth(),
		CheckAdmin: checkAdmin(),
		doLogin:    localDoLogin,
	}
}

func localDoLogin(ctx *gin.Context) (token string, userId int64, nickname string, err error) {
	var params dto.LoginParams
	if err = ctx.ShouldBind(&params); err != nil {
		return
	}
	return NativeLogin(ctx, &params)
}

func localUserAuth() gin.HandlerFunc {
	unauth := &gowk.ErrorCode{Status: http.StatusUnauthorized, Code: http.StatusUnauthorized, Msg: "认证失败"}
	return func(ctx *gin.Context) {
		id := gowk.LoginId(ctx)
		if id <= 0 {
			gowk.Fail(ctx, unauth)
			return
		}
		var svc service.UserService
		user, err := svc.GetById(ctx.Request.Context(), id)
		if err != nil {
			gowk.Fail(ctx, unauth)
			return
		}
		ctx.Set(ContextUserKey, &User{
			Id:       user.ID,
			Nickname: user.Nickname.String,
			Group:    user.Group.String,
		})
		ctx.Next()
	}
}

// ─── remote 模式 ───────────────────────────────────────────────────────────────

func setupRemote(router *gin.Engine, prefix string) *Middlewares {
	grpcAddr := os.Getenv("AUTH_GRPC_ADDR")
	if grpcAddr == "" {
		panic("auth: AUTH_MODE=remote 时必须配置 AUTH_GRPC_ADDR（如 auth:50051）")
	}
	c, err := authclient.NewAuthClient(grpcAddr, "", "")
	if err != nil {
		panic("auth: gRPC 客户端初始化失败: " + err.Error())
	}
	c.MountRemote(router, prefix)
	return &Middlewares{
		Login:      remoteLoginMW(c),
		UserAuth:   remoteUserAuth(c),
		CheckAdmin: checkAdmin(),
		doLogin:    remoteDoLogin(c),
	}
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

// ─── 原有公共 API（保持不变）──────────────────────────────────────────────────

// Mount 将 auth 的 HTTP 路由挂载到给定 prefix 下（如 "/api/auth"）。
func Mount(router *gin.Engine, prefix string) {
	g := router.Group(prefix)
	route.Router(g)
}

// NativeLogin 使用 auth 的用户校验逻辑，签发 gowk Redis token，供 local 模式登录使用。
func NativeLogin(ctx *gin.Context, params *dto.LoginParams) (token string, userID int64, nickname string, err error) {
	var userService service.UserService
	user, err := userService.Login(ctx.Request.Context(), params)
	if err != nil {
		return "", 0, "", err
	}
	token, err = gowk.Login(ctx, user.ID)
	if err != nil {
		return "", 0, "", err
	}
	return token, user.ID, user.Nickname.String, nil
}

// UserInfo 根据 userId 返回 nickname、group，供调用方填入 context（local 模式）。
func UserInfo(ctx context.Context, id int64) (userID int64, nickname, group string, err error) {
	if id <= 0 {
		return 0, "", "", gowk.NewError("invalid user id")
	}
	var userService service.UserService
	user, err := userService.GetById(ctx, id)
	if err != nil {
		return 0, "", "", err
	}
	return user.ID, user.Nickname.String, user.Group.String, nil
}
