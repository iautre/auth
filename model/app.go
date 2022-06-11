package model

import (
	"github.com/iautre/gowk"
)

type App struct {
	gowk.Model
	Name      string      `json:"name"`
	Remark    string      `json:"remark"`
	Key       string      `json:"key"`
	Secret    string      `json:"secret"`
	Resources []*Resource `json:"resources" gorm:"-"`
	Policies  []*Policy   `json:"policies" gorm:"-"`
}

type AppPolicy struct {
	gowk.Model
	AppId    uint
	PolicyId uint
}

func (a *App) Save() error {
	return gowk.DB().Save(a).Error
}
func (u *App) Update() error {
	// gowk.Mysql().Update()
	return nil
}

func (a *App) GetByName(name string) (*App, error) {
	app := &App{}
	if err := gowk.DB().Where("name = ?", name).First(app).Error; err != nil {
		return nil, err
	}
	return app, nil
}
func (a *App) GetByKey(key string) (*App, error) {
	app := &App{}
	if err := gowk.DB().First(app).Where("key = ?", key).Error; err != nil {
		return nil, err
	}
	return app, nil
}
