package service

import (
	"context"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/constant"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgtype"
)

// bootstrapAdminLockKey 是「首个管理员」判定用的咨询锁编号，取值来自 "auth_adm"，
// 只在本项目内使用，避免与其他业务的自增锁编号相撞。
const bootstrapAdminLockKey = int64(0x61757468_5F61646D)

// createUserWithBootstrapAdmin 建号，并在系统还没有任何管理员时把新账号提为管理员。
//
// 首次部署（或管理员被全部删除后）没有任何途径创建管理员：注册入口建出来的账号
// 都是 DEFAULT，而配置第三方 provider、管理 OAuth2 client 都要求管理员，会形成死锁。
// 这里让第一个出现的账号直接拿到 ADMIN，独立部署与作为库嵌入共用同一段逻辑。
//
// 判定放在带咨询锁的事务里：两个请求同时首建时，若各自读到「无管理员」就会双双提权，
// 因此必须串行化。
func createUserWithBootstrapAdmin(ctx context.Context, params db2.CreateUserParams) (db2.AuthUser, error) {
	tx, err := gowk.DB(ctx).Begin(ctx)
	if err != nil {
		return db2.AuthUser{}, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", bootstrapAdminLockKey); err != nil {
		return db2.AuthUser{}, err
	}

	queries := db2.New(tx)
	hasAdmin, err := queries.HasAdminUser(ctx)
	if err != nil {
		return db2.AuthUser{}, err
	}
	if !hasAdmin {
		params.Group = pgtype.Text{String: constant.USER_GROUP_ADMIN, Valid: true}
	}

	user, err := queries.CreateUser(ctx, params)
	if err != nil {
		return db2.AuthUser{}, friendlyUniqueViolation(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return db2.AuthUser{}, err
	}
	return user, nil
}
