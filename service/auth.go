package service

import (
	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/model"
	"github.com/iautre/gowk"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	UID  uint
	Auid uint
}

func NewAuthService(c *gin.Context) *AuthService {
	userId := c.GetUint("UID")
	auid := c.GetUint("AUID")
	return &AuthService{UID: userId, Auid: auid}
}

func (as *AuthService) Authenticate(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	//校验token
	js := NewJwtService()
	claims := js.CheckToken(token)
	c.Set("UID", claims.ID)
	c.Set("AUID", claims.Auid)
}

func (as *AuthService) GetQrcode(qrcodeType string) *model.Qrcode {
	if "weapp" == qrcodeType {
		weapp := NewWeapp()
		uuid := gowk.UUID()
		fileByte := weapp.GetUnlimited(uuid)

		//存缓存
		gowk.Cache().Set(uuid, &model.ConfirmAccess{
			Token:      uuid,
			ClientName: "",
		})
		return &model.Qrcode{
			Data: fileByte,
			Code: uuid,
		}
	}
	return nil
}

func (as *AuthService) GetToken(c *gin.Context) *model.Token {
	grantType := c.Query("grant_type")
	code := c.Query("code")
	var user *model.User
	userService := NewUserService(c)
	if "weapp" == grantType {
		if code == "" {
			gowk.Panic(gowk.NewErrorCode(500, "无code"))
		}
		//通过微信code获取用户
		user = userService.GetByWeApp(code)
	} else if "phone" == grantType {
		phone := c.Query("phone")
		//校验code
		if code != "789654" {
			gowk.Panic(gowk.NewErrorCode(500, "验证码错误"))
		}
		user = userService.GetByPhone(phone)
	} else if "weappscan" == grantType {
		//获取扫码结果
		confirmAccess := gowk.Cache().Get(code).(*model.ConfirmAccess)
		if confirmAccess == nil {
			gowk.Panic(gowk.NewErrorCode(500, "登陆二维码失效，请重新获取"))
		}
		if "" == confirmAccess.State {
			gowk.Panic(gowk.NewErrorCode(500, "等待扫码"))

		}
		if "scaned" == confirmAccess.State {
			gowk.Panic(gowk.NewErrorCode(500, "已扫码，等待确认"))

		}
		if "deny" == confirmAccess.State { //不同意
			gowk.Panic(gowk.NewErrorCode(500, "拒绝登陆"))

		}
		if "approve" == confirmAccess.State { //同意
			gowk.Cache().Del(code)
			user = userService.GetByAuid(confirmAccess.Auid)
		}
	} else if "basicauth" == grantType { //用户名密码
		username := c.Query("username")
		password := c.Query("password")
		user = userService.GetByPhone(username)

		//hash, err2 := bcrypt.GenerateFromPassword([]byte("4120edd84e61a11ecd1f902dfdd88eac"), bcrypt.DefaultCost) //加密处理
		//if err2 != nil {
		//	return nil, common.NewError("密码错误")
		//}
		//encodePWD := string(hash)                                                     // 保存在数据库的密码，虽然每次生成都不同，只需保存一份即可
		err2 := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) //验证（对比）
		if err2 != nil {
			gowk.Panic(gowk.NewErrorCode(500, "密码错误"))
		}
	} else {
		gowk.Panic(gowk.NewErrorCode(500, "无效"))
	}
	js := NewJwtService()
	tokenStr := js.CreateToken(user)
	return &model.Token{
		Token:    tokenStr,
		UserInfo: user,
	}
}

func (as *AuthService) ConfirmAccess(c *gin.Context, accessToken, confirmType string) *model.ConfirmAccess {
	confirmAccess := gowk.Cache().Get(accessToken).(*model.ConfirmAccess)
	if confirmAccess == nil {
		gowk.Panic(gowk.NewErrorCode(500, "登陆二维码失效，请重新获取"))

	}
	confirmAccess.Auid = as.Auid
	confirmAccess.State = confirmType
	if "scaned" == confirmType || "sended" == confirmType {
		return confirmAccess
	}
	gowk.Panic(gowk.NewErrorCode(500, "类型错误"))
	return nil
}
