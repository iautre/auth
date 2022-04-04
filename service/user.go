package service

import (
	"github.com/autrec/auth/model"
	"github.com/autrec/gowk"
	"github.com/gin-gonic/gin"
)

type UserService struct {
	gowk.Service
}

func NewUserService(c *gin.Context) *UserService {
	userService := &UserService{}
	userService.Ctx = c
	return userService
}

func (us *UserService) GetByWeApp(code string) (*model.User, error) {
	weapp := NewWeapp()
	openId, sessionKey, err := weapp.Code2Session(code)
	if err != nil {
		return nil, err
	}
	user := &model.User{}
	//查询用户信息
	err = user.GetByThridOpenId(openId)
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
	return user, nil
}

func (us *UserService) GetByAuid(auid uint) (*model.User, error) {
	user := &model.User{}
	err := user.GetByAuid(auid)
	return user, err
}
func (us *UserService) GetByEmail(email string) (*model.User, error) {
	user := &model.User{}
	err := user.GetByEmail(email)
	return user, err
}
func (us *UserService) GetByPhone(phone string) (*model.User, error) {
	user := &model.User{}
	err := user.GetByPhone(phone)
	if err != nil {
		gowk.Log().Error(us.Ctx, err.Error(), err)
		user.Phone = phone
		user.Auid = gowk.NewAuid()
	}
	user.Save()
	return user, nil
}

type UserThridService struct {
	// gowk.Service
}

func NewUserThridService(c *gin.Context) *UserThridService {
	ut := &UserThridService{}
	// ut.Ctx = c
	return ut
}
