// Package authctx 提供 Auth 在宿主进程内注入的用户上下文。
//
// 独立部署与包内嵌两种形态共用同一套类型：宿主业务代码通过 ContextUser 取当前用户，
// 不需要区分 Auth 是以独立服务还是进程内模块的形式存在。
package authctx

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/pkg/constant"
)

// ContextUserKey 是 gin.Context 中存放 *User 的键。
//
// 与 gowk.ContextLoginIdKey 的分工：后者只承载登录 ID，不查库；
// 本键承载已解析出的用户对象，由 UserAuth 中间件写入。
const ContextUserKey = "AUTH_CONTEXT_USER"

const (
	GroupAdmin   = constant.USER_GROUP_ADMIN
	GroupDefault = constant.USER_GROUP_DEFAULT
)

// User 是鉴权与展示所需的最小用户信息。
type User struct {
	Id       int64
	Nickname string
	Group    string
}

// IsAdmin 报告用户是否属于管理员组。nil 接收者返回 false。
// 组名比较不区分大小写，与 AdminMiddleware 的判定口径保持一致。
func (u *User) IsAdmin() bool { return u != nil && strings.EqualFold(u.Group, GroupAdmin) }

// ContextUser 返回当前请求的用户，未注入了返回 nil。
func ContextUser(ctx *gin.Context) *User {
	if ctx == nil {
		return nil
	}
	value, exists := ctx.Get(ContextUserKey)
	if !exists {
		return nil
	}
	user, _ := value.(*User)
	return user
}

// UserId 返回当前请求的用户 ID，未注入了返回 0。
func UserId(ctx *gin.Context) int64 {
	if user := ContextUser(ctx); user != nil {
		return user.Id
	}
	return 0
}
