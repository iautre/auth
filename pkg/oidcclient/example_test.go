package oidcclient_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/iautre/auth/pkg/oidcclient"
)

// ExampleNew 演示一次完整的授权码登录。真实使用时把 URL 参数换成
// http.Request 的 query，把 verifier 与 nonce 存进会话（cookie/session）。
func ExampleNew() {
	client, err := oidcclient.New(context.Background(), oidcclient.Config{
		// 与 Auth 的 gowk.BaseURL() 完全一致
		Issuer:       "https://auth.example.com",
		ClientID:     "console",
		ClientSecret: "请从 Auth 客户端管理获取",
		RedirectURL:  "https://console.example.com/auth/callback",
	})
	if err != nil {
		log.Fatal(err)
	}

	// 第一步：跳转到 Auth 登录页
	authURL, codeVerifier := client.AuthCodeURL("随机 state", oidcclient.AuthURLOptions{
		Nonce: "随机 nonce",
	})
	saveToSession(codeVerifier, "随机 nonce")
	_ = authURL

	// 第二步：回调里用授权码换 token
	token, err := client.Exchange(context.Background(), "回调里的 code", codeVerifier)
	if err != nil {
		log.Fatal(err)
	}

	// 第三步：校验 ID Token（签名 / iss / aud / 有效期 / nonce）
	idToken, err := client.VerifyIDToken(context.Background(), token.IDToken, "随机 nonce")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(idToken.Subject, idToken.Name, idToken.Email)

	// 需要更多字段时读 userinfo；access token 是不透明字符串不能自行解析
	userInfo, err := client.UserInfo(context.Background(), token.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(userInfo.PreferredUsername)

	// access token 过期后用 refresh token 换新的，rotation 后必须落盘新值
	if token.Expired() {
		refreshed, err := client.Refresh(context.Background(), token.RefreshToken)
		if err != nil {
			log.Fatal(err)
		}
		saveToSession(refreshed.RefreshToken)
	}
}

func saveToSession(_ ...string) {}

// 保证示例与真实用法一致：HTTP 服务里直接复用同一个 Client。
var _ = http.StatusOK
