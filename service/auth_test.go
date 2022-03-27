package service

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAuth(t *testing.T) {
	password := "0192023a7bbd73250516f069df18b500"
	hash, err2 := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) //加密处理
	if err2 != nil {
		fmt.Print(err2)
	}
	encodePWD := string(hash)
	fmt.Println(encodePWD)
	err2 = bcrypt.CompareHashAndPassword([]byte(encodePWD), []byte(password)) //验证（对比）
	if err2 != nil {
		fmt.Print(err2)
	}
}
