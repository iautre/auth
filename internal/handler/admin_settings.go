package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/internal/service"
	"github.com/iautre/gowk"
)

// settingsPageData 是系统设置页需要注入的接口地址。
type settingsPageData struct {
	AccountPath   string
	ProvidersPath string
	SettingsPath  string
	UsersPath     string
}

// SettingsPage 渲染系统设置页：第三方登录、注册开关、用户管理。
// 只有管理员能进，鉴权由路由上的 CheckLogin + CheckAdmin 完成。
func SettingsPage(ctx *gin.Context) {
	basePath := strings.TrimSuffix(ctx.Request.URL.Path, "/admin/settings")
	setBrowserPageHeaders(ctx)
	if err := browserPageTemplate.ExecuteTemplate(ctx.Writer, "settings.html", settingsPageData{
		AccountPath:   basePath + "/account",
		ProvidersPath: basePath + "/admin/identity-providers",
		SettingsPath:  basePath + "/admin/config",
		UsersPath:     basePath + "/admin/users",
	}); err != nil {
		ctx.Error(err)
	}
}

// ProvidersPageRedirect 把旧的 /admin/providers 指到系统设置页，保留已有书签。
func ProvidersPageRedirect(ctx *gin.Context) {
	basePath := strings.TrimSuffix(ctx.Request.URL.Path, "/admin/providers")
	ctx.Redirect(http.StatusFound, basePath+"/admin/settings")
}

func GetSettings(ctx *gin.Context) {
	gowk.Response(ctx, http.StatusOK, service.GetSystemSettings(ctx.Request.Context()), nil)
}

type settingsParams struct {
	RegistrationOpen bool `json:"registration_open"`
}

func UpdateSettings(ctx *gin.Context) {
	var params settingsParams
	if err := ctx.ShouldBindJSON(&params); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("参数不合法"))
		return
	}
	if err := service.UpdateSystemSettings(ctx.Request.Context(), service.SystemSettings{
		RegistrationOpen: params.RegistrationOpen,
	}); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, service.GetSystemSettings(ctx.Request.Context()), nil)
}

func ListUsers(ctx *gin.Context) {
	limit, _ := strconv.Atoi(ctx.Query("limit"))
	offset, _ := strconv.Atoi(ctx.Query("offset"))
	users, total, err := (&service.UserService{}).ListUsers(ctx.Request.Context(), ctx.Query("q"), limit, offset)
	if err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, gin.H{"items": users, "total": total}, nil)
}

type updateUserParams struct {
	Enabled *bool   `json:"enabled"`
	Group   *string `json:"group"`
}

func UpdateUser(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("invalid user ID"))
		return
	}
	// 不许改自己：否则唯一的管理员可能把自己禁用或降级，之后就没人能进后台了。
	if id == gowk.LoginId(ctx) {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("不能修改自己的账号"))
		return
	}
	var params updateUserParams
	if err := ctx.ShouldBindJSON(&params); err != nil || (params.Enabled == nil && params.Group == nil) {
		gowk.Response(ctx, http.StatusBadRequest, nil, gowk.NewError("没有要修改的字段"))
		return
	}
	if err := (&service.UserService{}).UpdateUser(ctx.Request.Context(), id, params.Enabled, params.Group); err != nil {
		gowk.Response(ctx, http.StatusBadRequest, nil, err)
		return
	}
	gowk.Response(ctx, http.StatusOK, gin.H{"ok": true}, nil)
}
