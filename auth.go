package auth

import (
	"errors"

	"github.com/autrec/auth/model"
	"github.com/autrec/auth/service"
	"github.com/autrec/gowk"
	"github.com/gin-gonic/gin"
)

// 认证
func AuthenticateMiddleware(ignore ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, url := range ignore {
			if c.Request.URL.Path == url {
				c.Next()
				return
			}
		}
		appService := service.NewAppService(c)
		//校验client
		app, err := appService.CheckApp(c)
		if err != nil {
			gowk.Response().Fail(c, gowk.ERR_NOAPP, err)
			return
		}
		//校验权限
		if appService.CheckPolicy(c, app) != nil {
			gowk.Response().Fail(c, gowk.ERR_DBERR, err)
			return
		}
		if service.NewAuthService(c).Authenticate(c) != nil {
			gowk.Response().Fail(c, gowk.ERR_DBERR, err)
			return
		}
		c.Next()
	}
}

func Routers(routerGroup *gin.RouterGroup) {
	NewAuthController().InitRouter(routerGroup)
	NewAppController().InitRouter(routerGroup.Group("/app"))
	NewUserController().InitRouter(routerGroup.Group("/user"))
}

type AuthController struct {
}

func NewAuthController() *AuthController {
	return &AuthController{}
}
func (auth *AuthController) InitRouter(routerGroup *gin.RouterGroup) {
	//获取token
	routerGroup.GET("/token", auth.GetToken)
	routerGroup.GET("/token/qrcode", auth.GetQrcode)
	routerGroup.GET("/token/smscode", auth.SendSmsCode)
	routerGroup.POST("/token/confirm_access", auth.ConfirmAccess)
}

//获取token
// GET: /token?grant_type=&code=
func (auth *AuthController) GetToken(c *gin.Context) {
	js := service.NewAuthService(c)
	js.GetToken(c)
}

//获取二维码
// GET: /token/qrcode
func (auth *AuthController) GetQrcode(c *gin.Context) {
	qrcodeType := c.Query("qrcode_type")
	if qrcodeType == "" {
		gowk.Response().Fail(c, gowk.ERR_PARAM, errors.New("无参数qrcode_type"))
		return
	}
	s := service.NewAuthService(c)
	q, err := s.GetQrcode(qrcodeType)
	if err != nil {
		gowk.Response().Fail(c, gowk.ERR, err)
	}
	gowk.Response().Success(c, q)
}

//发送验证码
// GET: /token/smscode?account=
func (auth *AuthController) SendSmsCode(c *gin.Context) {
	//account为空时图形返回验证码
	//account为手机号时，发送手机验证码
	//account为邮箱时，发送邮箱验证码
	res := make(map[string]string)
	account := c.Query("account")
	if account == "" {
		res["code"] = "235684"
	}
	res["code"] = "235684"
	gowk.Response().Success(c, res)
}

//确认token
// POST /token/confirm_access
func (auth *AuthController) ConfirmAccess(c *gin.Context) {
	accessToken := c.PostForm("access_token")
	confirmType := c.PostForm("confirm_type")
	service.NewAuthService(c).ConfirmAccess(c, accessToken, confirmType)
}

type UserController struct {
}

func NewUserController() *UserController {
	return &UserController{}

}
func (user *UserController) InitRouter(routerGroup *gin.RouterGroup) {
	routerGroup.POST("", user.Add)
}

func (user *UserController) Add(ctx *gin.Context) {
	u := &model.User{}
	if err := ctx.ShouldBind(u); err != nil {
		gowk.Response().Fail(ctx, gowk.ERR, err)
		return
	}
	if u.NickName == "" {
		gowk.Response().Fail(ctx, gowk.ERR, errors.New("请输入用户昵称"))
		return
	}
	if err := u.Save(); err != nil {
		gowk.Response().Fail(ctx, gowk.ERR, err)
		return
	}
	gowk.Response().Success(ctx, u)
}

type AppController struct {
}

func NewAppController() *AppController {
	return &AppController{}

}

func (app *AppController) InitRouter(routerGroup *gin.RouterGroup) {
	routerGroup.POST("", app.Add)
}

func (c *AppController) Add(ctx *gin.Context) {
	m := &model.App{}
	if err := ctx.ShouldBind(m); err != nil {
		gowk.Response().Fail(ctx, gowk.ERR, err)
		return
	}
	if m.Name == "" {
		gowk.Response().Fail(ctx, gowk.ERR, errors.New("请输入应用名"))
		return
	}
	service := service.NewAppService(ctx)
	res, err := service.Add(m.Name)
	if err != nil {
		gowk.Response().Fail(ctx, gowk.ERR, err)
		return
	}
	gowk.Response().Success(ctx, res)
}
