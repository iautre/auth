package model

import (
	"errors"
	"time"

	"github.com/autrec/gowk"
	"github.com/dgrijalva/jwt-go"
)

type Jwt struct {
	SigningKey []byte
	Claims     *Claims
}

type Claims struct {
	jwt.StandardClaims
	ID       string
	Auid     uint
	Role     []string
	Username string
}

func NewJWT() *Jwt {
	return &Jwt{
		SigningKey: []byte(gowk.Conf().GetString("jwt.signing.key")),
	}
}

func (j *Jwt) setClaims(claims *Claims) {
	j.Claims = claims
	now := time.Now()
	expires, _ := time.ParseDuration("24h")
	j.Claims.ExpiresAt = now.Add(expires).Unix()
	j.Claims.Issuer = "autre"
	j.Claims.IssuedAt = now.Unix()
}

func (j *Jwt) CreateToken(claims *Claims) (string, error) {
	j.setClaims(claims)
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, j.Claims)
	token, err := at.SignedString(j.SigningKey)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (j *Jwt) ParseToken(token string) (*Claims, error) {
	claim, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			// ValidationErrorMalformed是一个uint常量，表示token不可用
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, errors.New("token不可用")
				// ValidationErrorExpired表示Token过期
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, errors.New("token过期")
				// ValidationErrorNotValidYet表示无效token
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, errors.New("无效的token")
			} else {
				return nil, errors.New("token不可用")
			}
		}
		return nil, err
	}
	if claims, ok := claim.Claims.(*Claims); ok && claim.Valid {
		return claims, nil
	}
	return nil, errors.New("token无效")
}
