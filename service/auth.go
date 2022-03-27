package service

import (
	"errors"

	"github.com/autrec/auth/model"
	"github.com/autrec/gowk"
	"github.com/gin-gonic/gin"
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

func (as *AuthService) Authenticate(c *gin.Context) error {
	token := c.Request.Header.Get("Authorization")
	//校验token
	js := NewJwtService()
	claims, err := js.CheckToken(token)
	if err != nil {
		return err
	}
	c.Set("UID", claims.ID)
	c.Set("AUID", claims.Auid)
	return nil
}

func (as *AuthService) GetQrcode(qrcodeType string) (*model.Qrcode, error) {
	if "weapp" == qrcodeType {
		weapp := NewWeapp()
		uuid := gowk.UUID()
		fileByte, err := weapp.GetUnlimited(uuid)
		if err != nil {
			return nil, err
		}
		//存缓存
		gowk.Cache().Set(uuid, &model.ConfirmAccess{
			Token:      uuid,
			ClientName: "",
		})
		return &model.Qrcode{
			Data: fileByte,
			Code: uuid,
		}, nil
	}
	return nil, nil
}

func (as *AuthService) GetToken(c *gin.Context) {
	grantType := c.Query("grant_type")
	code := c.Query("code")
	var user *model.User
	var err error
	userService := NewUserService(c)
	if "weapp" == grantType {

		if code == "" {
			gowk.Response().Fail(c, gowk.ERR_DBERR, nil)
			return
		}
		//通过微信code获取用户
		user, err = userService.GetByWeApp(code)
		if err != nil {
			gowk.Response().Fail(c, gowk.ERR_DBERR, nil)
			return
		}
	} else if "phone" == grantType {
		phone := c.Query("phone")
		//校验code
		if code != "789654" {
			gowk.Response().Fail(c, gowk.ERR_DBERR, errors.New("验证码错误"))
			return
		}
		user, err = userService.GetByPhone(phone)
		if err != nil {
			gowk.Response().Fail(c, gowk.ERR_NODATA, nil)
			return
		}
	} else if "weappscan" == grantType {
		//获取扫码结果
		confirmAccess := gowk.Cache().Get(code).(*model.ConfirmAccess)
		if confirmAccess == nil {
			gowk.Response().Fail(c, gowk.ERR_DBERR, errors.New("登陆二维码失效，请重新获取"))
			return
		}
		if "" == confirmAccess.State {
			gowk.Response().Fail(c, gowk.ERR_DBERR, errors.New("等待扫码"))
			return
		}
		if "scaned" == confirmAccess.State {
			gowk.Response().Fail(c, gowk.ERR_DBERR, errors.New("已扫码，等待确认"))
			return
		}
		if "deny" == confirmAccess.State { //不同意
			gowk.Response().Fail(c, gowk.ERR_DBERR, errors.New("拒绝登陆"))
			return
		}
		if "approve" == confirmAccess.State { //同意
			gowk.Cache().Del(code)
			user, err = userService.GetByAuid(confirmAccess.Auid)
			if err != nil {
				gowk.Response().Fail(c, gowk.ERR_DBERR, nil)
				return
			}
		}
	} else if "basicauth" == grantType { //用户名密码
		username := c.Query("username")
		password := c.Query("password")
		user, err = userService.GetByPhone(username)
		if err != nil {
			gowk.Response().Fail(c, gowk.ERR_DBERR, err)
			return
		}
		//hash, err2 := bcrypt.GenerateFromPassword([]byte("4120edd84e61a11ecd1f902dfdd88eac"), bcrypt.DefaultCost) //加密处理
		//if err2 != nil {
		//	return nil, common.NewError("密码错误")
		//}
		//encodePWD := string(hash)                                                     // 保存在数据库的密码，虽然每次生成都不同，只需保存一份即可
		err2 := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) //验证（对比）
		if err2 != nil {
			gowk.Response().Fail(c, gowk.ERR_DBERR, errors.New("密码错误"))
			return
		}
	} else {
		gowk.Response().Fail(c, gowk.ERR_DBERR, nil)
		return
	}
	js := NewJwtService()
	token, err := js.CreateToken(user)
	response := make(map[string]interface{})
	response["token"] = token
	response["userInfo"] = user
	gowk.Response().Success(c, response)
}

func (as *AuthService) ConfirmAccess(c *gin.Context, accessToken, confirmType string) {
	confirmAccess := gowk.Cache().Get(accessToken).(*model.ConfirmAccess)
	if confirmAccess == nil {
		gowk.Response().Fail(c, gowk.ERR, errors.New("登陆二维码失效，请重新获取"))
		return
	}
	confirmAccess.Auid = as.Auid
	confirmAccess.State = confirmType
	if "scaned" == confirmType || "sended" == confirmType {
		gowk.Response().Success(c, confirmAccess)
		return
	}
	gowk.Response().Fail(c, gowk.ERR, errors.New("类型错误"))
}
