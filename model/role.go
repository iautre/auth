package model

type Role struct {
	Name     string
	Remark   string
	Policies []*Policy
}
