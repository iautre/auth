package service

import (
	"github.com/gin-gonic/gin"
	"github.com/iautre/auth/model"
	"github.com/iautre/gowk"
)

type AppService struct {
}

func NewAppService() *AppService {
	appService := &AppService{}
	return appService
}

func (as *AppService) CheckApp(c *gin.Context) *model.App {
	appKey := c.Request.Header.Get("App")
	//校验app
	c.Set("APPKEY", appKey)
	return as.CheckAppByKey(appKey)
}

func (as *AppService) CheckAppByKey(appKey string) *model.App {
	if appKey == "" {
		gowk.Panic(gowk.ERR_NOAPP)
	}
	//校验app
	var app *model.App
	app, err := app.GetByKey(appKey)
	if err != nil {
		gowk.Panic(gowk.ERR_NOAPP)
	}
	return app
}
func (as *AppService) CheckPolicy(c *gin.Context, app *model.App) {
}

func (as *AppService) Add(app *model.App) *model.App {
	app.Key = gowk.UUID()
	app.Secret = gowk.UUID64()
	//检测名字有吗
	if _, err := app.GetByName(app.Name); err == nil {
		gowk.Panic(gowk.NewErrorCode(500, "已有"))
	}
	if err := app.Save(); err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "保存失败"))
	}
	return app
}
