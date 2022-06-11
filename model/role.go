package model

import "github.com/iautre/gowk"

type Role struct {
	gowk.Model
	Name     string    `json:"name,omitempty"`
	Remark   string    `json:"remark,omitempty"`
	Policies []*Policy `json:"policies,omitempty" gorm:"-"`
}

type RolePolicy struct {
	gowk.Model
	RoleId   uint
	PolicyId uint
}
