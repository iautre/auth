package model

import "github.com/iautre/gowk"

type Policy struct {
	gowk.Model
	Name       string
	Remark     string
	AppId      uint
	ResourceId uint
	Apps       []*App      `json:"apps" gorm:"-"`
	Resources  []*Resource `json:"resources" gorm:"-"`
}
