package model

type Role struct {
	Name     string    `json:name,omitempty`
	Remark   string    `json:remark,omitempty`
	Policies []*Policy `json:policies,omitempty`
}
