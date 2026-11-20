package service

import (
	"context"
	"strings"
	"time"

	"github.com/iautre/auth/pkg/constant"
	"github.com/iautre/gowk"
)

// AdminUser 是用户管理列表的一行。
type AdminUser struct {
	ID          int64     `json:"id"`
	Email       string    `json:"email"`
	Phone       string    `json:"phone"`
	Nickname    string    `json:"nickname"`
	Group       string    `json:"group"`
	Enabled     bool      `json:"enabled"`
	LastLoginAt time.Time `json:"last_login_at"`
	Created     time.Time `json:"created"`
}

// ListUsers 按关键词分页查询用户。关键词同时匹配邮箱、手机号、昵称。
func (u *UserService) ListUsers(ctx context.Context, query string, limit, offset int) ([]AdminUser, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	pattern := "%" + strings.TrimSpace(query) + "%"

	const filter = ` COALESCE(email, '') ILIKE $1
		OR COALESCE(phone, '') ILIKE $1
		OR COALESCE(nickname, '') ILIKE $1 `

	var total int64
	if err := gowk.DB(ctx).QueryRow(ctx,
		`SELECT count(*) FROM public.auth_user WHERE `+filter, pattern,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := gowk.DB(ctx).Query(ctx,
		`SELECT id,
		        COALESCE(email, ''),
		        COALESCE(phone, ''),
		        COALESCE(nickname, ''),
		        COALESCE("group", $2),
		        enabled,
		        COALESCE(last_login_at, to_timestamp(0)),
		        created
		 FROM public.auth_user
		 WHERE `+filter+`
		 ORDER BY id DESC
		 LIMIT $3 OFFSET $4`,
		pattern, constant.USER_GROUP_DEFAULT, limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	users := make([]AdminUser, 0, limit)
	for rows.Next() {
		var item AdminUser
		if err := rows.Scan(&item.ID, &item.Email, &item.Phone, &item.Nickname,
			&item.Group, &item.Enabled, &item.LastLoginAt, &item.Created); err != nil {
			return nil, 0, err
		}
		users = append(users, item)
	}
	return users, total, rows.Err()
}

// UpdateUser 修改用户的启用状态与分组；传 nil 表示不改该项。
func (u *UserService) UpdateUser(ctx context.Context, id int64, enabled *bool, group *string) error {
	if id <= 0 {
		return gowk.NewError("invalid user ID")
	}
	if group != nil {
		normalized := strings.ToUpper(strings.TrimSpace(*group))
		if normalized != constant.USER_GROUP_ADMIN && normalized != constant.USER_GROUP_DEFAULT {
			return gowk.NewError("invalid group")
		}
		*group = normalized
	}

	tag, err := gowk.DB(ctx).Exec(ctx,
		`UPDATE public.auth_user
		 SET enabled = COALESCE($2, enabled),
		     "group" = COALESCE($3, "group"),
		     updated = now()
		 WHERE id = $1`, id, enabled, group)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return gowk.NewError("user not found")
	}
	return nil
}
