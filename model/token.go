package model

type Token struct {
	Token    string `json:"token,omitempty"`
	UserInfo *User  `json:"userInfo,omitempty"`
}
