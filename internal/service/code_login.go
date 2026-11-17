package service

import (
	"context"
	"errors"
	"strings"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/constant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// 验证码用途常量，与数据库 CHECK 约束保持一致。
const (
	PurposeLogin       = "login"
	PurposeRegister    = "register"
	PurposeVerifyEmail = "verify_email"
)

// 登录与建号路径共用的可判别错误。
var (
	ErrInvalidCredentials = errors.New("账号或凭据不正确")
	ErrAccountDisabled    = errors.New("账号已被停用")
	ErrEmailTaken         = errors.New("邮箱已被占用")
)

// LoginWithCode 用邮箱验证码登录。
//
// 邮箱不存在时按 autoRegister 决定：放开就顺手建号（注册即登录），
// 不放开则仍返回凭据错误，避免通过提示语探测某个邮箱是否已注册。
func (s *UserService) LoginWithCode(ctx context.Context, email, code string, autoRegister bool) (db2.AuthUser, error) {
	target := normalizeTarget(email)

	var verificationService VerificationService
	if err := verificationService.Verify(ctx, target, PurposeLogin, code); err != nil {
		return db2.AuthUser{}, err
	}

	user, err := s.getQueries(ctx).UserByEmail(ctx, target)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return db2.AuthUser{}, err
		}
		if !autoRegister {
			return db2.AuthUser{}, ErrInvalidCredentials
		}
		return s.createUserByEmail(ctx, target)
	}

	if !user.Enabled {
		return db2.AuthUser{}, ErrAccountDisabled
	}
	return user, nil
}

// RegisterWithCode 用邮箱验证码完成注册；邮箱已存在则返回占用错误。
func (s *UserService) RegisterWithCode(ctx context.Context, email, code string) (db2.AuthUser, error) {
	target := normalizeTarget(email)

	var verificationService VerificationService
	if err := verificationService.Verify(ctx, target, PurposeRegister, code); err != nil {
		return db2.AuthUser{}, err
	}

	user, err := s.getQueries(ctx).UserByEmail(ctx, target)
	if err == nil {
		return user, ErrEmailTaken
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return db2.AuthUser{}, err
	}
	return s.createUserByEmail(ctx, target)
}

// createUserByEmail 用邮箱直接建号：账号只有邮箱，昵称用打码后的邮箱。
func (s *UserService) createUserByEmail(ctx context.Context, email string) (db2.AuthUser, error) {
	return createUserWithBootstrapAdmin(ctx, db2.CreateUserParams{
		Email:      pgtype.Text{String: email, Valid: true},
		Nickname:   pgtype.Text{String: maskTarget(email), Valid: true},
		Group:      pgtype.Text{String: constant.USER_GROUP_DEFAULT, Valid: true},
		IsVerified: pgtype.Bool{Bool: true, Valid: true},
	})
}

// maskTarget 生成一个不泄露完整信息的默认昵称。
func maskTarget(email string) string {
	if at := strings.Index(email, "@"); at > 1 {
		return email[:1] + "***" + email[at:]
	}
	return "用户"
}

// friendlyUniqueViolation 把唯一索引冲突翻译成可读错误。
func friendlyUniqueViolation(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "uq_auth_user_email_lower") {
		return ErrEmailTaken
	}
	return err
}
