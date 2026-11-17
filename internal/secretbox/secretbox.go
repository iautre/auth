// Package secretbox 统一处理 auth 落库的敏感列加密。
//
// 覆盖范围：第三方 provider 的 client_secret、OAuth2 client 的 secret、
// OIDC JWK 私钥。密文带 "enc:v1:" 前缀，无前缀的值按明文原样返回，
// 因此存量明文数据可以平滑读取，逐条重写时自动升级为密文。
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/iautre/gowk"
)

// EnvKey 是 AES-256 主密钥的环境变量名，值可以是 base64 或 hex 编码的 32 字节。
const EnvKey = "AUTH_ENCRYPTION_KEY"

const (
	cipherPrefix = "enc:v1:"
	// aad 固定为常量：不区分字段，避免换字段后解不开，也够防住跨用途的密文挪用。
	aad = "auth-secretbox-v1"
)

var (
	once    sync.Once
	initErr error
	aead    cipher.AEAD
	// plaintext 为真表示没有配置密钥，Seal 原样返回、Open 原样透传。
	plaintext bool
)

// Init 读取 AUTH_ENCRYPTION_KEY 并初始化 AEAD，幂等。
//
// 未配置密钥时：BASE_URL 为 http（本地开发）降级为明文模式并打警告；
// 非 http 部署直接返回错误，由调用方终止启动——生产环境静默存明文不可接受。
func Init() error {
	once.Do(func() {
		raw := strings.TrimSpace(os.Getenv(EnvKey))
		if raw == "" {
			if isProductionDeployment() {
				initErr = fmt.Errorf("%s 未配置：非 http 部署必须提供 32 字节密钥（base64 或 hex）", EnvKey)
				return
			}
			plaintext = true
			slog.Warn("auth secretbox: 未配置 " + EnvKey + "，敏感列将以明文落库（仅允许本地 http 开发）")
			return
		}

		key, err := decodeKey(raw)
		if err != nil {
			initErr = err
			return
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			initErr = fmt.Errorf("secretbox: 初始化 AES 失败: %w", err)
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			initErr = fmt.Errorf("secretbox: 初始化 GCM 失败: %w", err)
			return
		}
		aead = gcm
	})
	return initErr
}

// Enabled 表示当前是否处于加密模式。
func Enabled() bool {
	if err := Init(); err != nil {
		return false
	}
	return aead != nil
}

// Seal 加密一个敏感值。明文模式或空串原样返回。
func Seal(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if err := Init(); err != nil {
		return "", err
	}
	if aead == nil {
		return value, nil
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretbox: 生成随机数失败: %w", err)
	}

	sealed := aead.Seal(nil, nonce, []byte(value), []byte(aad))
	out := append(nonce, sealed...)
	return cipherPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open 解密一个敏感值。无密文前缀的值视为存量明文，原样返回。
func Open(stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, cipherPrefix) {
		return stored, nil
	}
	if err := Init(); err != nil {
		return "", err
	}
	if aead == nil {
		return "", errors.New("secretbox: 数据已加密但未配置 " + EnvKey + "，无法解密")
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, cipherPrefix))
	if err != nil {
		return "", fmt.Errorf("secretbox: 密文格式错误: %w", err)
	}
	if len(raw) < aead.NonceSize() {
		return "", errors.New("secretbox: 密文长度不足")
	}

	nonce, body := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, body, []byte(aad))
	if err != nil {
		return "", fmt.Errorf("secretbox: 解密失败（密钥是否变更？）: %w", err)
	}
	return string(plain), nil
}

// IsSealed 判断一个存储值是否已经加密。
func IsSealed(stored string) bool {
	return strings.HasPrefix(stored, cipherPrefix)
}

func decodeKey(raw string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	return nil, fmt.Errorf("secretbox: %s 必须是 base64 或 hex 编码的 32 字节", EnvKey)
}

func isProductionDeployment() bool {
	base := strings.TrimSpace(gowk.BaseURL())
	return base != "" && !strings.HasPrefix(base, "http://")
}
