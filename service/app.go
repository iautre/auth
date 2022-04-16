package service

import (
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
	app := &model.App{}
	if err := app.GetByKey(appKey); err != nil {
		gowk.Panic(gowk.ERR_NOAPP)
	}
	return app
}
func (as *AppService) CheckPolicy(c *gin.Context, app *model.App) {

}

func (as *AppService) Add(post *model.App) *model.App {
	post.Key = gowk.UUID()
	post.Secret = gowk.UUID64()
	//检测名字有吗
	app := &model.App{}
	if err := app.GetByName(post.Name); err == nil {
		gowk.Panic(gowk.NewErrorCode(500, "已有"))
	}
	if err := post.Save(); err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "保存失败"))
	}
	return post
}
