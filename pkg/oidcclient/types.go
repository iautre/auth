package oidcclient

import "time"

// Token 是一次授权码交换或刷新得到的凭据集合。
type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	// Expiry 是 access token 的绝对过期时刻；ID Token 的有效期与之相同。
	Expiry  time.Time
	IDToken string
	Scope   string
}

// Expired 预留 30 秒余量，避免临界时刻带着已失效的 token 发请求。
func (t *Token) Expired() bool {
	if t == nil || t.Expiry.IsZero() {
		return true
	}
	return time.Now().After(t.Expiry.Add(-30 * time.Second))
}

// Claims 是本服务实现的标准声明子集，ID Token 与 userinfo 端点共用。
// 具体返回哪些字段取决于授权时申请的 scope（profile / email / phone）。
type Claims struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PhoneNumber       string `json:"phone_number"`
	PhoneVerified     bool   `json:"phone_number_verified"`
}

// IDToken 是校验通过的 ID Token，额外携带协议层声明。
type IDToken struct {
	Claims
	Issuer   string
	Audience []string
	Expiry   time.Time
	IssuedAt time.Time
	Nonce    string
	// Raw 是解码后的完整声明，用于读取本包未列出的自定义字段。
	Raw map[string]any
}

// UserInfo 是 userinfo 端点的返回结果。
type UserInfo struct {
	Claims
	Raw map[string]any
}

// Endpoints 是从 discovery 文档中取到的端点地址，便于调试与日志。
type Endpoints struct {
	Issuer        string
	Authorization string
	Token         string
	UserInfo      string
	JWKS          string
}
