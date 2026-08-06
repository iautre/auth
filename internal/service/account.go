package service

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func (u *UserService) UpdateProfile(ctx context.Context, userID int64, params dto.ProfileUpdateParams) (db2.AuthUser, error) {
	phone := strings.TrimSpace(params.Phone)
	email := strings.ToLower(strings.TrimSpace(params.Email))
	nickname := strings.TrimSpace(params.Nickname)
	if !isValidPhone(phone) {
		return db2.AuthUser{}, gowk.NewError("手机号格式不正确")
	}
	parsedEmail, err := mail.ParseAddress(email)
	if err != nil || parsedEmail.Address != email || len(email) > 254 {
		return db2.AuthUser{}, gowk.NewError("邮箱格式不正确")
	}
	if nickname == "" || len([]rune(nickname)) > 50 {
		return db2.AuthUser{}, gowk.NewError("昵称需要填写且不能超过 50 个字符")
	}
	rows, err := u.getQueries(ctx).UpdateUserProfile(ctx, db2.UpdateUserProfileParams{
		ID:       userID,
		Phone:    pgtype.Text{String: phone, Valid: true},
		Email:    pgtype.Text{String: email, Valid: true},
		Nickname: pgtype.Text{String: nickname, Valid: true},
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return db2.AuthUser{}, gowk.NewError("手机号或邮箱已被其他账号使用")
		}
		return db2.AuthUser{}, err
	}
	if rows != 1 {
		return db2.AuthUser{}, gowk.NewError("用户不存在")
	}
	return u.GetById(ctx, userID)
}
