package auth

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/model"
	"github.com/iautre/auth/service"
	"github.com/iautre/gowk"
)

// 认证
func AuthenticateMiddleware(ignores ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, ignore := range ignores {
			arr := strings.Split(ignore, ":")
			if len(arr) == 2 {
				method := strings.ToUpper(arr[0])
				url := arr[1]
				if c.Request.Method == method && c.Request.URL.Path == url {
					c.Next()
					return
				}
			}
			if len(arr) == 1 {
				if c.Request.URL.Path == arr[0] {
					c.Next()
					return
				}
			}
		}
		appService := service.NewAppService()
		//校验client
		app := appService.CheckApp(c)
		//校验权限
		appService.CheckPolicy(c, app)
		//校验token
		service.NewAuthService(c).Authenticate(c)
		c.Next()
	}
}

// get:/token
// get:/qrcode
// get:/smscode
// post:/confirm_access
// post:/app
// post:/user
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
	routerGroup.GET("/qrcode", auth.GetQrcode)
	routerGroup.GET("/smscode", auth.SendSmsCode)
	routerGroup.POST("/confirm_access", auth.ConfirmAccess)
}

//获取token
// GET: /token?grant_type=&code=
func (auth *AuthController) GetToken(c *gin.Context) {
	js := service.NewAuthService(c)
	token := js.GetToken(c)
	gowk.Response().Success(c, token)
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
	q := s.GetQrcode(qrcodeType)
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
	service := service.NewAppService()
	res := service.Add(m)
	gowk.Response().Success(ctx, res)
}

func GetClaims(token string) *model.Claims {
	jwtS := service.NewJwtService()
	return jwtS.CheckToken(token)
}

func CheckApp(appKey string) *model.App {
	appS := service.NewAppService()
	return appS.CheckAppByKey(appKey)
}
