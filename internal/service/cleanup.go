package service

import (
	"context"
	"log/slog"
	"sync"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/gowk"
)

// 过期数据清理间隔。授权码 10 分钟过期、access/refresh token 数小时到数十天，
// 每 10 分钟扫一遍足够，代价是三条带索引的 DELETE。
const defaultCleanupInterval = 10 * time.Minute

var cleanupOnce sync.Once

// StartCleanup 启动后台清理，重复调用只生效一次。
// 数据库是授权码与令牌的真相源（缓存层不影响写入），因此无论是否启用缓存都需要清理。
func StartCleanup() {
	cleanupOnce.Do(func() {
		go func() {
			// 启动时先清一次：进程长期不重启时不必等满一个周期才处理历史积压。
			cleanupOnceNow()

			ticker := time.NewTicker(defaultCleanupInterval)
			defer ticker.Stop()
			for range ticker.C {
				cleanupOnceNow()
			}
		}()
	})
}

func cleanupOnceNow() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	runCleanup(ctx)
}

func runCleanup(ctx context.Context) {
	pool := gowk.DB(ctx)
	if pool == nil {
		return
	}
	queries := db2.New(pool)

	if err := queries.CleanupExpiredAuthorizationCodes(ctx); err != nil {
		slog.WarnContext(ctx, "cleanup expired authorization codes failed", "err", err)
	}
	if err := queries.CleanupExpiredTokens(ctx); err != nil {
		slog.WarnContext(ctx, "cleanup expired access tokens failed", "err", err)
	}
	if err := queries.CleanupExpiredRefreshTokens(ctx); err != nil {
		slog.WarnContext(ctx, "cleanup expired refresh tokens failed", "err", err)
	}
}
