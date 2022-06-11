package model

import "github.com/iautre/gowk"

type Resource struct {
	gowk.Model
	appId  uint
	Method string
	Api    string
	Remark string
}
