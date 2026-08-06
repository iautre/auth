package handler

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
)

const gowkRedisTokenPrefix = "ATOKEN_TOKEN_"

func (u *UserHandler) UpdateProfile(ctx *gin.Context) {
	var params dto.ProfileUpdateParams
	if err := ctx.ShouldBindJSON(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("请完整填写手机号、邮箱和昵称"))
		return
	}
	var users service.UserService
	user, err := users.UpdateProfile(ctx, gowk.LoginId(ctx), params)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, userResponse(user), nil)
}

func (u *UserHandler) Logout(ctx *gin.Context) {
	if token := gowk.TokenValue(ctx); token != "" && gowk.HasRedis() {
		if redisClient := gowk.Redis(); redisClient != nil {
			if err := redisClient.Del(ctx, gowkRedisTokenPrefix+token).Err(); err != nil {
				slog.WarnContext(ctx, "revoke browser session failed", "err", err)
			}
		} else {
			slog.WarnContext(ctx, "revoke browser session skipped because Redis is not ready")
		}
	}
	ctx.SetCookie("oidc_jwt", "", -1, "/", "", true, true)
	gowk.Response(ctx, http.StatusOK, map[string]string{"message": "logged out"}, nil)
}

func userResponse(user db2.AuthUser) dto.UserRes {
	return dto.UserRes{
		Id:          user.ID,
		Phone:       user.Phone.String,
		Email:       user.Email.String,
		Nickname:    user.Nickname.String,
		Group:       user.Group.String,
		Avatar:      user.Avatar.String,
		IsVerified:  user.IsVerified.Bool,
		Enabled:     user.Enabled,
		LastLoginAt: user.LastLoginAt.Time.Format("2006-01-02T15:04:05Z"),
		Created:     user.Created.Time.Format("2006-01-02T15:04:05Z"),
	}
}
