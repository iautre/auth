package service

import (
	"github.com/iautre/auth/model"
	"github.com/iautre/gowk"
)

type JwtService struct {
}

func NewJwtService() *JwtService {
	return &JwtService{}
}

func (js *JwtService) CreateToken(user *model.User) string {

	jm := model.NewJWT()
	//创建token
	token, err := jm.CreateToken(&model.Claims{
		ID:   user.ID,
		Auid: user.Auid,
	})
	if err != nil {
		gowk.Panic(gowk.ERR_TOKEN)
	}
	return token
}

func (js *JwtService) CheckToken(token string) *model.Claims {
	// 通过http header中的token解析来认证

	if token == "" {
		gowk.Panic(gowk.NewErrorCode(11, "请求未携带token，无权限访问"))
	}

	// 初始化一个JWT对象实例，并根据结构体方法来解析token
	j := model.NewJWT()
	// 解析token中包含的相关信息(有效载荷)
	claims, err := j.ParseToken(token)

	if err != nil {
		// token过期
		gowk.Panic(gowk.NewErrorCode(11, "认证失败"))
	}

	// 将解析后的有效载荷claims重新写入gin.Context引用对象中
	return claims
}
