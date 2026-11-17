package config

import (
	"os"
	"strconv"
	"strings"
)

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return defaultValue
	}
	return parsed
}

var authAPIPrefix = getEnv("AUTH_API_PREFIX", "")

func AuthAPIPrefix() string {
	prefix := authAPIPrefix
	if prefix == "" {
		return ""
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return prefix
}

// AutoRegister 控制验证码登录时目标账号不存在是否自动建号。
// 默认开启，与"第三方 OIDC 一键注册"的预期一致。
func AutoRegister() bool {
	return getEnvBool("AUTH_AUTO_REGISTER", true)
}

// FederatedEnabled 控制第三方 OIDC 登录（auth 作为 RP）是否开放。
// 默认开启；库里没有启用的 provider 时实际不会有任何入口。
func FederatedEnabled() bool {
	return getEnvBool("AUTH_FEDERATED_ENABLED", true)
}
