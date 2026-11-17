package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/gowk"
)

var (
	errEmptyToken       = errors.New("empty access token")
	errTokenWithoutUser = errors.New("access token is not associated with a user")
)

// MCPAuth 是 MCP 端点的鉴权中间件，同时接受两类凭据：
//   - Authorization: Bearer <OAuth2 access token>：第三方 MCP 客户端经标准
//     授权码流程拿到 token 后走这条；
//   - 浏览器会话（cookie 或 gowk 自签发的 Bearer）：内置页面与本机调用走这条。
//
// 两种凭据都不成立时按 RFC 9728 回 401，并在 WWW-Authenticate 里给出资源
// 元数据地址——这是客户端唯一的发现入口，缺了它客户端无法自行找到授权服务器。
//
// metadataURL 是资源的元数据绝对地址。宿主挂载自己的 MCP 端点时，用
// authhttp.MCPAuth 传入自己的资源路径即可得到同名行为。
func MCPAuth(metadataURL string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if token, ok := strings.CutPrefix(ctx.GetHeader("Authorization"), "Bearer "); ok {
			if oauth2Token, err := validateMCPAccessToken(ctx, strings.TrimSpace(token)); err == nil {
				ctx.Set(gowk.ContextLoginIdKey, oauth2Token.UserID)
				ctx.Set(gowk.ContextTokenValueKey, oauth2Token.AccessToken)
				ctx.Next()
				return
			}
		}

		if probeBrowserCredential(ctx) {
			ctx.Next()
			return
		}

		writeMCPUnauthorized(ctx, metadataURL)
	}
}

// validateMCPAccessToken 校验 OAuth2 access token 并确认它绑定了具体用户。
// client_credentials 签发的 token 没有 user_id（为 0），不能用来调用
// 依赖登录身份的工具，因此直接拒绝。
func validateMCPAccessToken(ctx *gin.Context, accessToken string) (*db2.AuthOauth2Token, error) {
	if accessToken == "" {
		return nil, errEmptyToken
	}
	var oauth2Service service.OAuth2Service
	token, err := oauth2Service.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if token.UserID <= 0 {
		return nil, errTokenWithoutUser
	}
	return token, nil
}

// probeBrowserCredential 用一份不写真实响应的探针执行浏览器会话校验，
// 通过时把身份键复制回真实请求上下文。
func probeBrowserCredential(ctx *gin.Context) bool {
	probe := ctx.Copy()
	probe.Writer = newProbeResponseWriter()
	gowk.CheckLogin(probe)

	loginID := gowk.LoginId(probe)
	if loginID <= 0 {
		return false
	}
	ctx.Set(gowk.ContextLoginIdKey, loginID)
	if token := gowk.TokenInfo(probe); token != nil {
		ctx.Set(gowk.ContextTokenKey, token)
	}
	if value := gowk.TokenValue(probe); value != "" {
		ctx.Set(gowk.ContextTokenValueKey, value)
	}
	return true
}

func writeMCPUnauthorized(ctx *gin.Context, metadataURL string) {
	ctx.Header("WWW-Authenticate", `Bearer resource_metadata="`+metadataURL+`"`)
	gowk.Response(ctx, http.StatusUnauthorized, nil, gowk.NewError("Authentication required"))
}
