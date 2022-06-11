package model

import (
	"github.com/iautre/gowk"
)

type User struct {
	gowk.Model
	Auid     uint         `json:"auid,omitempty"`
	NickName string       `json:"nickName,omitempty" `
	Email    string       `json:"email,omitempty"`
	Phone    string       `json:"phone,omitempty"`
	Password string       `json:"password,omitempty"`
	Avatar   string       `json:"avatar,omitempty"`
	Thrids   []*UserThrid `json:"thrids,omitempty" gorm:"-"`
	Roles    []*Role      `json:"roles,omitempty" gorm:"-"`
	Policies []*Policy    `json:"policies,omitempty" gorm:"-"`
}

type UserRole struct {
	gowk.Model
	UserId uint
	RoleId uint
}

func NewUser() *User {
	return &User{}
}

type UserThrid struct {
	gowk.Model
	UserId      uint   `json:"uerId,omitempty" bson:"uerId,omitempty"`
	OpenType    string `json:"openType,omitempty" bson:"openType,omitempty"`
	OpenId      string `json:"openId,omitempty" bson:"openId,omitempty"`
	OpenName    string `json:"openName,omitempty" bson:"openName,omitempty"`
	AccessToken string `json:"accessToken,omitempty" bson:"accessToken,omitempty"`
	SessionKey  string `json:"sessionKey,omitempty" bson:"sessionKey,omitempty"`
	ExpiresIn   string `json:"expiresIn" bson:"expiresIn,omitempty"`
}

func (u *User) Save() error {
	if err := gowk.DB().Save(u).Error; err != nil {
		return err
	}
	return nil
}
func (u *User) Update() error {

	return nil
}
func (u *User) GetByThridOpenId(openId string) (*User, error) {
	if err := gowk.DB().Where("open_id = ?", openId).First(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}
func (u *User) GetByAuid(auid uint) (*User, error) {
	if err := gowk.DB().Where("auid = ?", auid).First(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}
func (u *User) GetByEmail(email string) (*User, error) {
	if err := gowk.DB().Where("email = ?", email).First(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}
func (u *User) GetByPhone(phone string) (*User, error) {
	user := &User{}
	if err := gowk.DB().Where("phone = ?", phone).First(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}
