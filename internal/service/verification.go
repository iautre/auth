package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	verificationCodeTTL      = 10 * time.Minute
	verificationResendWindow = 60 * time.Second
	verificationDailyLimit   = 10
	verificationMaxAttempts  = 5
)

// ChannelEmail 是验证码唯一的发送通道。
// auth_verification_code 仍保留 channel 列（后续可能重新支持短信），写库时固定填这个值。
const ChannelEmail = "email"

// emailPattern 只做形状校验：一个 @、两侧非空白、域名带点。
// 真正能不能收到信由发信通道决定，这里不做 RFC 5322 全量匹配。
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// 验证码相关的可判别错误。
var (
	ErrCodeInvalid         = errors.New("验证码不正确")
	ErrCodeExpired         = errors.New("验证码已过期，请重新获取")
	ErrCodeTooManyAttempts = errors.New("验证码尝试次数过多，请重新获取")
	ErrCodeRateLimited     = errors.New("发送太频繁，请稍后再试")
	ErrCodeDailyLimit      = errors.New("今日发送次数已达上限")
	ErrInvalidTarget       = errors.New("邮箱格式不正确")
)

// VerificationService 负责一次性验证码的签发、下发与核销。
type VerificationService struct {
	BaseService
}

// normalizeTarget 统一邮箱大小写与空白，保证限速和查询命中同一条。
func normalizeTarget(target string) string {
	return strings.ToLower(strings.TrimSpace(target))
}

// Send 生成并下发邮箱验证码。
func (s *VerificationService) Send(ctx context.Context, email, purpose string) error {
	target := normalizeTarget(email)
	if err := validateTarget(target); err != nil {
		return err
	}
	if currentMailer() == nil {
		return ErrChannelNotConfigured
	}

	queries := s.getQueries(ctx)
	now := time.Now()

	recent, err := queries.CountVerificationCodesSince(ctx, db2.CountVerificationCodesSinceParams{
		Channel: ChannelEmail,
		Target:  target,
		Purpose: purpose,
		Created: pgtype.Timestamptz{Time: now.Add(-verificationResendWindow), Valid: true},
	})
	if err != nil {
		return err
	}
	if recent > 0 {
		return ErrCodeRateLimited
	}

	daily, err := queries.CountVerificationCodesByTargetSince(ctx, db2.CountVerificationCodesByTargetSinceParams{
		Target:  target,
		Created: pgtype.Timestamptz{Time: now.Add(-24 * time.Hour), Valid: true},
	})
	if err != nil {
		return err
	}
	if daily >= verificationDailyLimit {
		return ErrCodeDailyLimit
	}

	code, err := generateNumericCode()
	if err != nil {
		return err
	}

	if _, err := queries.InsertVerificationCode(ctx, db2.InsertVerificationCodeParams{
		Channel:  ChannelEmail,
		Target:   target,
		Purpose:  purpose,
		CodeHash: hashVerificationCode(target, purpose, code),
		Expires:  pgtype.Timestamptz{Time: now.Add(verificationCodeTTL), Valid: true},
	}); err != nil {
		return err
	}

	return currentMailer().SendCode(ctx, target, code)
}

// Verify 核销验证码。成功返回 nil 并把该码标记为已消费。
func (s *VerificationService) Verify(ctx context.Context, email, purpose, code string) error {
	target := normalizeTarget(email)
	code = strings.TrimSpace(code)
	if code == "" {
		return ErrCodeInvalid
	}

	queries := s.getQueries(ctx)
	record, err := queries.LatestVerificationCode(ctx, db2.LatestVerificationCodeParams{
		Channel: ChannelEmail,
		Target:  target,
		Purpose: purpose,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCodeInvalid
		}
		return err
	}

	if record.Attempts >= verificationMaxAttempts {
		return ErrCodeTooManyAttempts
	}
	if time.Now().After(record.Expires.Time) {
		return ErrCodeExpired
	}

	want := hashVerificationCode(target, purpose, code)
	if subtle.ConstantTimeCompare([]byte(want), []byte(record.CodeHash)) != 1 {
		if err := queries.IncrementVerificationAttempts(ctx, record.ID); err != nil {
			return err
		}
		return ErrCodeInvalid
	}

	consumed, err := queries.ConsumeVerificationCode(ctx, record.ID)
	if err != nil {
		return err
	}
	if consumed == 0 {
		// 并发下被别的请求抢先消费，等同于码已失效。
		return ErrCodeInvalid
	}
	return nil
}

func validateTarget(target string) error {
	if target == "" || !emailPattern.MatchString(target) {
		return ErrInvalidTarget
	}
	return nil
}

// hashVerificationCode 把目标/用途一起揉进摘要，
// 同一个码发往不同目标得到不同摘要，库里的摘要无法跨目标复用。
func hashVerificationCode(target, purpose, code string) string {
	sum := sha256.Sum256([]byte(target + ":" + purpose + ":" + code))
	return hex.EncodeToString(sum[:])
}

func generateNumericCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("生成验证码失败: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
