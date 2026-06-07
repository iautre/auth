package handler

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/gowk"
)

// MqttHandler 处理 EMQX 的 HTTP 认证回调。
//
// EMQX「客户端认证」配置为 HTTP 服务时，每次客户端 CONNECT 都会带
// {clientid, username, password} 回调本接口。password 即认证凭据：
//   - 人（app 用户）：gowk native 登录 token（Redis ATOKEN_TOKEN_*）
//   - 应用（console / phone-agent）：OAuth2 client_credentials access_token（DB）
//
// 任一校验通过即放行，返回 EMQX 5 约定的 {"result":"allow"}；否则 {"result":"deny"}。
type MqttHandler struct {
	oauth2Service *service.OAuth2Service
}

func NewMqttHandler(ctx context.Context) *MqttHandler {
	return &MqttHandler{oauth2Service: service.NewOAuth2Service(ctx)}
}

type mqttAuthRequest struct {
	ClientID string `json:"clientid" form:"clientid"`
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

// Auth 是 EMQX HTTP authenticator 的回调入口。
func (h *MqttHandler) Auth(ctx *gin.Context) {
	if key := os.Getenv("EMQX_AUTH_KEY"); key != "" {
		if subtle.ConstantTimeCompare([]byte(ctx.GetHeader("X-Emqx-Key")), []byte(key)) != 1 {
			ctx.JSON(http.StatusOK, gin.H{"result": "deny"})
			return
		}
	}

	var req mqttAuthRequest
	if err := ctx.ShouldBind(&req); err != nil || req.Password == "" {
		ctx.JSON(http.StatusOK, gin.H{"result": "deny"})
		return
	}

	if h.allow(ctx.Request.Context(), req.Password) {
		ctx.JSON(http.StatusOK, gin.H{"result": "allow"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"result": "deny"})
}

// allow 依次尝试 native 登录 token 与 OAuth2 access_token，任一有效即放行。
// Redis 未就绪时跳过 native token 分支（不 panic），仍可走 OAuth2（DB）校验。
func (h *MqttHandler) allow(ctx context.Context, token string) bool {
	if rdb := gowk.Redis(); rdb != nil {
		if jsonData, err := rdb.Get(ctx, redisTokenPrefix+token).Result(); err == nil {
			var t nativeToken
			if json.Unmarshal([]byte(jsonData), &t) == nil {
				if t.Timeout <= 0 || t.CreatedAt <= 0 || time.Now().Unix() <= t.CreatedAt+t.Timeout {
					return true
				}
			}
		}
	}

	if _, err := h.oauth2Service.ValidateAccessToken(ctx, token); err == nil {
		return true
	}
	return false
}
