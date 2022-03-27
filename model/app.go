package model

import (
	"context"

	"github.com/autrec/gowk"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type App struct {
	Name      string      `json:"name" bson:"name,omitempty"`
	Remark    string      `json:"remark" bson:"remark,omitempty"`
	Key       string      `json:"key" bson:"key,omitempty"`
	Secret    string      `json:"secret" bson:"secret,omitempty"`
	Resources []*Resource `json:"resources" bson:"resources,omitempty"`
	Roles     []*Role     `json:"roles" bson:"roles,omitempty"`
	Policies  []*Policy   `json:"policies" bson:"policies,omitempty"`
}

func (App) TableName() string {
	return "auth_app"
}
func (App) DBName() string {
	return "autre_auth"
}

func (a *App) Collection() *mongo.Collection {
	return gowk.Mongo().Database(a.DBName()).Collection(a.TableName())
}
func (a *App) Save() error {
	_, err := a.Collection().InsertOne(context.TODO(), a)
	if err != nil {
		return err
	}
	return nil
}
func (u *App) Update() error {

	return nil
}

func (a *App) GetByName(name string) error {
	return a.Collection().FindOne(context.TODO(), bson.M{"name": name}).Decode(a)

}
func (a *App) GetByKey(key string) error {
	return a.Collection().FindOne(context.TODO(), bson.M{"key": key}).Decode(a)

}
