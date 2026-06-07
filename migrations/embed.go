// Package migrations 通过 embed.FS 打包 auth 的数据库迁移脚本，
// 由 gowk.AddMigrations 注册、在服务启动时自动按版本顺序执行。
//
// 新增迁移：在本目录添加 NNNN_描述.sql（版本号递增、唯一），无需改动其他代码。
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
