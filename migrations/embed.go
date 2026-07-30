// Package migrations 通过 embed.FS 打包 auth 的数据库迁移脚本，
// 由 gowk.AddMigrations 注册、在服务启动时自动按版本顺序执行。
//
// 新增迁移：在本目录按 1000001-1999999 保留段递增添加 NNNN_描述.sql，无需改动其他代码。
package migrations

import (
	"embed"
	"sync"

	"github.com/iautre/gowk"
)

//go:embed *.sql
var FS embed.FS

const (
	authMigrationMin = int64(1_000_001)
	authMigrationMax = int64(1_999_999)
)

var registerOnce sync.Once

// Register 将 auth 的迁移来源幂等注册到 gowk。
// auth 使用独立保留版本段，因此可与宿主应用自己的迁移同时注册。
func Register() {
	registerOnce.Do(func() {
		gowk.AddMigrations(FS, ".")
	})
}
