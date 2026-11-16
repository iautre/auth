package config

import (
	"os"
	"strings"
)

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
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
