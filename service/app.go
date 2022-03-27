package service

import (
	"errors"

	"github.com/autrec/auth/model"
	"github.com/autrec/gowk"
	"github.com/gin-gonic/gin"
)

type AppService struct {
	gowk.Service
}

func NewAppService(c *gin.Context) *AppService {
	appService := &AppService{}
	appService.Ctx = c
	return appService
}

func (as *AppService) CheckApp(c *gin.Context) (*model.App, error) {
	appKey := c.Request.Header.Get("App")
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

func (as *AppService) Add(name string) (*model.App, error) {
	post := &model.App{
		Name:   name,
		Key:    gowk.UUID(),
		Secret: gowk.UUID64(),
	}
	//检测名字有吗
	app := &model.App{}
	if err := app.GetByName(name); err != nil {
		return nil, errors.New("已有")
	}
	if err := post.Save(); err != nil {
		return nil, err
	}
	return post, nil
}
