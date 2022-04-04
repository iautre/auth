package service

import (
	"errors"

	"github.com/autrec/auth/model"
	"github.com/autrec/gowk"
	"github.com/gin-gonic/gin"
)

type AppService struct {
}

func NewAppService() *AppService {
	appService := &AppService{}
	return appService
}

func (as *AppService) CheckApp(c *gin.Context) (*model.App, error) {
	appKey := c.Request.Header.Get("App")
	//校验app
	c.Set("APPKEY", appKey)
	return as.CheckAppByKey(appKey)
}

func (as *AppService) CheckAppByKey(appKey string) (*model.App, error) {
	if appKey == "" {
		return nil, errors.New("无效appkey")
	}
	//校验app
	app := &model.App{}
	if err := app.GetByKey(appKey); err != nil {
		return nil, err
	}
	return app, nil
}
func (as *AppService) CheckPolicy(c *gin.Context, app *model.App) error {

	return nil
}

func (as *AppService) Add(post *model.App) (*model.App, error) {
	post.Key = gowk.UUID()
	post.Secret = gowk.UUID64()
	//检测名字有吗
	app := &model.App{}
	if err := app.GetByName(post.Name); err == nil {
		return nil, errors.New("已有")
	}
	if err := post.Save(); err != nil {
		return nil, err
	}
	return post, nil
}
