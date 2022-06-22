package service

import (
	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/model"
	"github.com/iautre/gowk"
)

type UserService struct {
	Ctx *gin.Context
}

func NewUserService(c *gin.Context) *UserService {
	userService := &UserService{
		Ctx: c,
	}
	return userService
}

func (us *UserService) GetByWeApp(code string) *model.User {
	weapp := NewWeapp()
	openId, sessionKey := weapp.Code2Session(code)

	var user *model.User
	//查询用户信息
	user, err := user.GetByThridOpenId(openId)
	if err != nil {
		user.Thrids = make([]*model.UserThrid, 0)
		userThrid := &model.UserThrid{
			OpenType:   "weapp",
			OpenId:     openId,
			SessionKey: sessionKey,
			OpenName:   "weapp",
		}
		user.Thrids = append(user.Thrids, userThrid)
	}
	user.Save()
	return user
}

func (us *UserService) GetByAuid(auid uint) *model.User {
	var user *model.User
	user, err := user.GetByAuid(auid)
	if err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "获取用户失败"), err)
	}
	return user
}
func (us *UserService) GetByEmail(email string) *model.User {
	var user *model.User
	user, err := user.GetByEmail(email)
	if err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "获取用户失败"), err)
	}
	return user
}
func (us *UserService) GetByPhone(phone string) *model.User {
	var user *model.User
	user, err := user.GetByPhone(phone)
	if err != nil {
		gowk.Log().Error(us.Ctx, err.Error(), err)
		user = &model.User{}
		user.Phone = phone
		user.Auid = user.NewAuid()
	}
	if err := user.Save(); err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "保存用户失败"), err)
	}
	return user
}

type UserThridService struct {
	// gowk.Service
}

func NewUserThridService(c *gin.Context) *UserThridService {
	ut := &UserThridService{}
	// ut.Ctx = c
	return ut
}
