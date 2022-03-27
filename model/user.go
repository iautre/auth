package model

import (
	"context"

	"github.com/autrec/gowk"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Auid     uint               `json:"auid" bson:"auid,omitempty"`
	NickName string             `json:"nickName" bson:"nickName,omitempty"`
	Email    string             `json:"email" bson:"email,omitempty"`
	Phone    string             `json:"phone" bson:"phone,omitempty"`
	Password string             `json:"password" bson:"password,omitempty"`
	Avatar   string             `json:"avatar" bson:"avatar,omitempty"`
	Thrids   []*UserThrid       `bson:"thrids,omitempty"`
	Roles    []*Role            `bson:"sroles,omitempty"`
	Policies []*Policy          `bson:"policies,omitempty"`
}

func (User) TableName() string {
	return "auth_user"
}
func (User) DBName() string {
	return "autre_auth"
}

func NewUser() *User {
	return &User{}
}

type UserThrid struct {
	UserId      uint   `json:"uerId,omitempty" bson:"uerId,omitempty"`
	OpenType    string `json:"openType,omitempty" bson:"openType,omitempty"`
	OpenId      string `json:"openId,omitempty" bson:"openId,omitempty"`
	OpenName    string `json:"openName,omitempty" bson:"openName,omitempty"`
	AccessToken string `json:"accessToken,omitempty" bson:"accessToken,omitempty"`
	SessionKey  string `json:"sessionKey,omitempty" bson:"sessionKey,omitempty"`
	ExpiresIn   string `json:"expiresIn" bson:"expiresIn,omitempty"`
}

func (UserThrid) TableName() string {
	return "auth_user_thrid"
}
func (UserThrid) DBName() string {
	return "autre_auth"
}
func (u *User) Collection() *mongo.Collection {
	return gowk.Mongo().Database(u.DBName()).Collection(u.TableName())
}
func (u *User) Save() error {
	iResult, err := u.Collection().InsertOne(context.TODO(), u)
	if err != nil {
		return err
	}
	id := iResult.InsertedID.(primitive.ObjectID)
	u.ID = id
	return nil
}
func (u *User) Update() error {

	return nil
}
func (u *User) GetByThridOpenId(openId string) error {
	return u.Collection().FindOne(context.TODO(), bson.M{"thrids.openId": openId}).Decode(u)
}
func (u *User) GetByAuid(auid uint) error {
	return u.Collection().FindOne(context.TODO(), bson.M{"auid": auid}).Decode(u)
}
func (u *User) GetByEmail(email string) error {
	return u.Collection().FindOne(context.TODO(), bson.M{"email": email}).Decode(u)
}
func (u *User) GetByPhone(phone string) error {
	return u.Collection().FindOne(context.TODO(), bson.M{"phone": phone}).Decode(u)
}
