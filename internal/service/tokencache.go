package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

// access token 校验是 OIDC 唯一的读热路径（每次调 userinfo 都查一次库），
// 因此在显式配置 OAUTH2_TOKEN_CACHE=redis 时加一层只读缓存。
// 数据库始终是真相源：缓存未命中、Redis 不可用都直接回源，不影响正确性。
const (
	accessTokenCachePrefix = "auth:oauth2:at:"
	// 缓存寿命取 token 剩余有效期与该上限的较小值。禁用 client 的生效延迟
	// 同样受这个上限约束，因此不宜设太长。
	accessTokenCacheTTL = 60 * time.Second
	// 启动期连通性探测的超时。
	tokenCacheProbeTimeout = 3 * time.Second
)

var tokenCacheEnabled = strings.EqualFold(strings.TrimSpace(os.Getenv("OAUTH2_TOKEN_CACHE")), "redis")

// InitTokenCache 校验缓存后端在启动阶段确实可用。
// 配置了 OAUTH2_TOKEN_CACHE=redis 却连不上时返回错误，由调用方终止启动：
// 静默退化为不缓存会让"配了 Redis"这个判断失去意义。
func InitTokenCache() error {
	if !tokenCacheEnabled {
		return nil
	}
	addr := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if addr == "" {
		return errors.New("OAUTH2_TOKEN_CACHE=redis 需要同时配置 REDIS_ADDR")
	}

	// 不使用 gowk.Redis()：它是后台异步 Ping 通后才发布的，启动瞬间通常为 nil，
	// 用它做启动校验会误判为不可用。这里独立建一个临时客户端做一次同步探测。
	client := redis.NewClient(&redis.Options{
		Addr:       addr,
		Password:   os.Getenv("REDIS_PASSWORD"),
		DB:         redisDBNumber(),
		MaxRetries: 1,
	})
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), tokenCacheProbeTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("OAUTH2_TOKEN_CACHE=redis 但 Redis 不可达（%s）: %w", addr, err)
	}

	slog.Info("OAuth2 access token 缓存已启用", "backend", "redis", "addr", addr)
	return nil
}

func redisDBNumber() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("REDIS_DB")))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// cachedAccessToken 是落进 Redis 的最小字段集，避免把 pgtype 结构整体序列化。
type cachedAccessToken struct {
	AccessToken string    `json:"access_token"`
	ClientID    string    `json:"client_id"`
	UserID      int64     `json:"user_id"`
	Scope       string    `json:"scope"`
	Expires     time.Time `json:"expires"`
}

func accessTokenCacheKey(token string) string {
	return accessTokenCachePrefix + token
}

// loadAccessTokenFromCache 命中时返回 token，未命中或缓存不可用时返回 nil。
func loadAccessTokenFromCache(ctx context.Context, token string) *db2.AuthOauth2Token {
	if !tokenCacheEnabled {
		return nil
	}
	client := gowk.Redis()
	if client == nil {
		return nil
	}
	raw, err := client.Get(ctx, accessTokenCacheKey(token)).Bytes()
	if err != nil {
		// redis.Nil 是正常未命中；其余错误只记录，不阻断请求。
		if !errors.Is(err, redis.Nil) {
			slog.WarnContext(ctx, "read access token cache failed", "err", err)
		}
		return nil
	}
	var entry cachedAccessToken
	if err := json.Unmarshal(raw, &entry); err != nil {
		slog.WarnContext(ctx, "decode cached access token failed", "err", err)
		return nil
	}
	if !entry.Expires.After(time.Now()) {
		return nil
	}
	return &db2.AuthOauth2Token{
		AccessToken: entry.AccessToken,
		TokenType:   "Bearer",
		ClientID:    entry.ClientID,
		UserID:      entry.UserID,
		Scope:       pgtype.Text{String: entry.Scope, Valid: entry.Scope != ""},
		Expires:     pgtype.Timestamptz{Time: entry.Expires, Valid: true},
	}
}

// storeAccessTokenToCache 把刚查到的 token 写入缓存，TTL 取剩余有效期与上限的较小值。
func storeAccessTokenToCache(ctx context.Context, token *db2.AuthOauth2Token) {
	if !tokenCacheEnabled || token == nil {
		return
	}
	client := gowk.Redis()
	if client == nil {
		return
	}
	remaining := time.Until(token.Expires.Time)
	if remaining <= 0 {
		return
	}
	ttl := accessTokenCacheTTL
	if remaining < ttl {
		ttl = remaining
	}
	entry := cachedAccessToken{
		AccessToken: token.AccessToken,
		ClientID:    token.ClientID,
		UserID:      token.UserID,
		Scope:       token.Scope.String,
		Expires:     token.Expires.Time,
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		slog.WarnContext(ctx, "encode access token for cache failed", "err", err)
		return
	}
	if err := client.Set(ctx, accessTokenCacheKey(token.AccessToken), raw, ttl).Err(); err != nil {
		slog.WarnContext(ctx, "write access token cache failed", "err", err)
	}
}

// revokeAccessTokenCache 在显式撤销时删掉缓存，避免已撤销的 token 继续命中。
func revokeAccessTokenCache(ctx context.Context, token string) {
	if !tokenCacheEnabled || token == "" {
		return
	}
	client := gowk.Redis()
	if client == nil {
		return
	}
	if err := client.Del(ctx, accessTokenCacheKey(token)).Err(); err != nil {
		slog.WarnContext(ctx, "delete access token cache failed", "err", err)
	}
}
