package service

import (
	"context"
	"strings"

	"github.com/iautre/auth/internal/config"
	"github.com/iautre/gowk"
)

// 系统设置的键名。值存文本，读取时统一按布尔解析。
const SettingRegistrationOpen = "registration_open"

// SystemSettings 是系统设置页面上可编辑的项。
type SystemSettings struct {
	RegistrationOpen bool `json:"registration_open"`
}

// RegistrationOpen 决定验证码登录遇到未注册账号时是否自动建号。
// 数据库里有显式配置时以它为准，否则回退 AUTH_AUTO_REGISTER（默认开启）。
func RegistrationOpen(ctx context.Context) bool {
	pool := gowk.DB(ctx)
	if pool == nil {
		return config.AutoRegister()
	}
	var value string
	err := pool.QueryRow(ctx,
		`SELECT value FROM public.auth_system_setting WHERE key = $1`,
		SettingRegistrationOpen,
	).Scan(&value)
	if err != nil {
		return config.AutoRegister()
	}
	if open, ok := parseSettingBool(value); ok {
		return open
	}
	return config.AutoRegister()
}

// GetSystemSettings 读取当前设置，未配置的项按默认值返回。
func GetSystemSettings(ctx context.Context) SystemSettings {
	return SystemSettings{RegistrationOpen: RegistrationOpen(ctx)}
}

// UpdateSystemSettings 写入设置。用 upsert 保证重复保存不报主键冲突。
func UpdateSystemSettings(ctx context.Context, settings SystemSettings) error {
	_, err := gowk.DB(ctx).Exec(ctx,
		`INSERT INTO public.auth_system_setting (key, value, updated)
		 VALUES ($1, $2, now())
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated = now()`,
		SettingRegistrationOpen, formatSettingBool(settings.RegistrationOpen),
	)
	return err
}

func formatSettingBool(open bool) string {
	if open {
		return "true"
	}
	return "false"
}

func parseSettingBool(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "on", "yes":
		return true, true
	case "false", "0", "off", "no":
		return false, true
	}
	return false, false
}
