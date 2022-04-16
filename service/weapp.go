package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/autrec/auth/model"
	"github.com/autrec/gowk"
)

const (
	appid  = "wxd713c74ef777d96d"
	secret = "256932c1e4215a71b3d883a3c3fb42cd"
	page   = "pages/user/auth"
)

type Weapp struct {
	AccessToken string
	ExpiresIn   int64
}

var weapp = &Weapp{}

func NewWeapp() *Weapp {
	return weapp
}

func (w *Weapp) GetAccessToken() string {
	if time.Now().Unix() > w.ExpiresIn {
		w.AuthGetAccessToken()
	}
	return w.AccessToken
}

//获取accesstoken
func (w *Weapp) AuthGetAccessToken() {
	w.ExpiresIn = time.Now().Unix()
	url := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s", appid, secret)
	resp, err := http.Get(url)
	//关闭资源
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "请求微信异常"))
	}
	jMap := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&jMap)
	if err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "解析微信报文异常"))
	}
	if jMap["errcode"] == nil || jMap["errcode"] == 0 {
		w.AccessToken, _ = jMap["access_token"].(string)
		w.ExpiresIn = w.ExpiresIn + int64(jMap["expires_in"].(float64))
	} else {
		//返回错误信息
		errcode := jMap["errcode"].(string)
		errmsg := jMap["errmsg"].(string)
		gowk.Panic(gowk.NewErrorCode(500, fmt.Sprintf("v%:v%", errcode, errmsg)))
	}
}

//获取二维码
func (w *Weapp) GetUnlimited(uuid string) []byte {
	token := w.GetAccessToken()
	if token == "" {
		gowk.Panic(gowk.NewErrorCode(500, "token为空"))
	}
	url := fmt.Sprintf("https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=%s", token)
	req := model.WxacodeunlimitReq{
		//AccessToken: w.AccessToken,
		Scene: uuid,
		Page:  page,
	}
	reqJson, err := json.Marshal(req)
	if err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "解析json错误"))
	}
	resp, err := http.Post(url, "application/json; encoding=utf-8", bytes.NewReader(reqJson))
	if err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "请求错误"))
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "请求错误"))
	}
	return content
}

// code换取session openID等信息
func (w *Weapp) Code2Session(code string) (string, string) {

	url := fmt.Sprintf("https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code", appid, secret, code)
	resp, err := http.Get(url)
	//关闭资源
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		gowk.Panic(gowk.NewErrorCode(500, "请求错误"))
	}
	jMap := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&jMap)
	if int64(jMap["errcode"].(float64)) == 0 {
		return jMap["openid"].(string), jMap["session_key"].(string)
	}
	return "", ""
}
