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
	PurposeVerifyPhone = "verify_phone"
)

// 登录与建号路径共用的可判别错误。
var (
	ErrInvalidCredentials = errors.New("账号或凭据不正确")
	ErrAccountDisabled    = errors.New("账号已被停用")
	ErrEmailTaken         = errors.New("邮箱已被占用")
	ErrPhoneTaken         = errors.New("手机号已被占用")
)

// LoginWithCode 用短信/邮箱验证码登录。
//
// 目标账号不存在时按 autoRegister 决定：放开就顺手建号（注册即登录），
// 不放开则仍返回凭据错误，避免通过提示语探测某个手机号/邮箱是否已注册。
func (s *UserService) LoginWithCode(ctx context.Context, channel, target, code string, autoRegister bool) (db2.AuthUser, error) {
	target = normalizeTarget(channel, target)

	var verificationService VerificationService
	if err := verificationService.Verify(ctx, channel, target, PurposeLogin, code); err != nil {
		return db2.AuthUser{}, err
	}

	queries := s.getQueries(ctx)
	user, err := s.findUserByTarget(ctx, queries, channel, target)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return db2.AuthUser{}, err
		}
		if !autoRegister {
			return db2.AuthUser{}, ErrInvalidCredentials
		}
		return s.createUserByTarget(ctx, queries, channel, target)
	}

	if !user.Enabled {
		return db2.AuthUser{}, ErrAccountDisabled
	}
	return user, nil
}

// RegisterWithCode 用验证码完成注册；目标已存在则直接返回占用错误。
func (s *UserService) RegisterWithCode(ctx context.Context, channel, target, code string) (db2.AuthUser, error) {
	target = normalizeTarget(channel, target)

	var verificationService VerificationService
	if err := verificationService.Verify(ctx, channel, target, PurposeRegister, code); err != nil {
		return db2.AuthUser{}, err
	}

	queries := s.getQueries(ctx)
	user, err := s.findUserByTarget(ctx, queries, channel, target)
	if err == nil {
		if channel == ChannelEmail {
			return user, ErrEmailTaken
		}
		return user, ErrPhoneTaken
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return db2.AuthUser{}, err
	}
	return s.createUserByTarget(ctx, queries, channel, target)
}

func (s *UserService) findUserByTarget(ctx context.Context, queries *db2.Queries, channel, target string) (db2.AuthUser, error) {
	switch channel {
	case ChannelEmail:
		return queries.UserByEmail(ctx, target)
	case ChannelSMS:
		return queries.UserByPhone(ctx, pgtype.Text{String: target, Valid: true})
	default:
		return db2.AuthUser{}, errors.New("不支持的验证通道: " + channel)
	}
}

// createUserByTarget 用手机号或邮箱直接建号：账号只有手机号/邮箱，昵称用打码后的目标。
func (s *UserService) createUserByTarget(ctx context.Context, queries *db2.Queries, channel, target string) (db2.AuthUser, error) {
	params := db2.CreateUserParams{
		Nickname:   pgtype.Text{String: maskTarget(channel, target), Valid: true},
		Group:      pgtype.Text{String: constant.USER_GROUP_DEFAULT, Valid: true},
		IsVerified: pgtype.Bool{Bool: true, Valid: true},
	}
	if channel == ChannelEmail {
		params.Email = pgtype.Text{String: target, Valid: true}
	} else {
		params.Phone = pgtype.Text{String: target, Valid: true}
	}

	user, err := queries.CreateUser(ctx, params)
	if err != nil {
		return db2.AuthUser{}, friendlyUniqueViolation(err)
	}
	return user, nil
}

// maskTarget 生成一个不泄露完整信息的默认昵称。
func maskTarget(channel, target string) string {
	if channel == ChannelSMS && len(target) >= 7 {
		return target[:3] + "****" + target[len(target)-4:]
	}
	if channel == ChannelEmail {
		if at := strings.Index(target, "@"); at > 1 {
			return target[:1] + "***" + target[at:]
		}
	}
	return "用户"
}

// friendlyUniqueViolation 把唯一索引冲突翻译成可读错误。
func friendlyUniqueViolation(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "uq_auth_user_email_lower"):
		return ErrEmailTaken
	case strings.Contains(msg, "uq_auth_user_phone"):
		return ErrPhoneTaken
	}
	return err
}
