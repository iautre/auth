package service

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/pkg/util"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgtype"
)

const otpEnrollmentTTL = 10 * time.Minute

type OTPService struct {
	BaseService
}

type OTPCredentialSummary struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Created    time.Time  `json:"created"`
}

type OTPEnrollmentBeginResult struct {
	FlowToken  string `json:"flow_token"`
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (s *OTPService) ListCredentials(ctx context.Context, userID int64) ([]OTPCredentialSummary, error) {
	if userID <= 0 {
		return nil, gowk.NewError("invalid user ID")
	}
	records, err := s.getQueries(ctx).ListOtpCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list OTP credentials: %w", err)
	}
	result := make([]OTPCredentialSummary, 0, len(records))
	for _, record := range records {
		var lastUsedAt *time.Time
		if record.LastUsedAt.Valid {
			value := record.LastUsedAt.Time
			lastUsedAt = &value
		}
		result = append(result, OTPCredentialSummary{
			ID:         record.ID,
			Name:       record.Name,
			LastUsedAt: lastUsedAt,
			Created:    record.Created.Time,
		})
	}
	return result, nil
}

func (s *OTPService) BeginEnrollment(ctx context.Context, userID int64, name string) (*OTPEnrollmentBeginResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "OTP"
	}
	if len([]rune(name)) > 50 {
		return nil, gowk.NewError("OTP 名称不能超过 50 个字符")
	}
	var users UserService
	user, err := users.GetById(ctx, userID)
	if err != nil {
		return nil, err
	}
	secret, err := util.GenerateOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("generate OTP secret: %w", err)
	}
	token := gowk.GenerateRandomString(32)
	expires := time.Now().Add(otpEnrollmentTTL)
	if err := s.getQueries(ctx).CreateOtpEnrollment(ctx, db2.CreateOtpEnrollmentParams{
		Token:   token,
		UserID:  userID,
		Name:    name,
		Secret:  secret,
		Expires: pgtype.Timestamptz{Time: expires, Valid: true},
	}); err != nil {
		return nil, fmt.Errorf("store OTP enrollment: %w", err)
	}
	_, _ = s.getQueries(ctx).DeleteExpiredOtpEnrollments(ctx)

	account := strings.TrimSpace(user.Email.String)
	if account == "" {
		account = strings.TrimSpace(user.Phone.String)
	}
	if account == "" {
		account = fmt.Sprintf("user-%d", user.ID)
	}
	return &OTPEnrollmentBeginResult{
		FlowToken:  token,
		Secret:     secret,
		OTPAuthURL: otpAuthURL(otpIssuer(), account, secret),
		ExpiresAt:  expires.Unix(),
	}, nil
}

func (s *OTPService) FinishEnrollment(ctx context.Context, userID int64, flowToken, code string) error {
	if userID <= 0 || strings.TrimSpace(flowToken) == "" || len(code) != 6 {
		return gowk.NewError("无效的 OTP 绑定请求")
	}
	enrollment, err := s.getQueries(ctx).GetOtpEnrollment(ctx, db2.GetOtpEnrollmentParams{Token: flowToken, UserID: userID})
	if err != nil {
		return gowk.NewError("OTP 绑定请求已失效，请重新开始")
	}
	var otp util.OTP
	if !otp.CheckCode(enrollment.Secret, code) {
		return gowk.NewError("验证码不正确")
	}
	return withLockedUserCredentials(ctx, userID, func(queries *db2.Queries) error {
		rows, err := queries.ConsumeOtpEnrollment(ctx, db2.ConsumeOtpEnrollmentParams{Token: flowToken, UserID: userID})
		if err != nil {
			return err
		}
		if rows != 1 {
			return gowk.NewError("OTP 绑定请求已失效，请重新开始")
		}
		_, err = queries.CreateOtpCredential(ctx, db2.CreateOtpCredentialParams{
			UserID: userID,
			Name:   enrollment.Name,
			Secret: enrollment.Secret,
		})
		return err
	})
}

func (s *OTPService) DeleteCredential(ctx context.Context, userID, credentialID int64) (bool, error) {
	if userID <= 0 || credentialID <= 0 {
		return false, gowk.NewError("invalid OTP credential")
	}
	deleted := false
	err := withLockedUserCredentials(ctx, userID, func(queries *db2.Queries) error {
		rows, err := queries.DeleteOtpCredentialByUser(ctx, db2.DeleteOtpCredentialByUserParams{ID: credentialID, UserID: userID})
		deleted = rows == 1
		if err != nil || !deleted {
			return err
		}
		return ensureAuthenticationMethodRemains(ctx, queries, userID)
	})
	return deleted, err
}

func (s *OTPService) VerifyLogin(ctx context.Context, userID int64, code string) (bool, error) {
	records, err := s.getQueries(ctx).ListOtpSecretsByUser(ctx, userID)
	if err != nil {
		return false, err
	}
	var otp util.OTP
	for _, record := range records {
		if !otp.CheckCode(record.Secret, code) {
			continue
		}
		_, err := s.getQueries(ctx).UpdateOtpCredentialAfterLogin(ctx, db2.UpdateOtpCredentialAfterLoginParams{
			ID: record.ID, UserID: userID,
		})
		return true, err
	}
	return false, nil
}

func (s *OTPService) ResetCredentials(ctx context.Context, userID int64) (string, error) {
	secret, err := util.GenerateOTPSecret()
	if err != nil {
		return "", fmt.Errorf("generate OTP secret: %w", err)
	}
	err = withLockedUserCredentials(ctx, userID, func(queries *db2.Queries) error {
		if _, err := queries.DeleteAllOtpCredentialsByUser(ctx, userID); err != nil {
			return err
		}
		_, err := queries.CreateOtpCredential(ctx, db2.CreateOtpCredentialParams{
			UserID: userID,
			Name:   "管理员重置",
			Secret: secret,
		})
		return err
	})
	return secret, err
}

func otpIssuer() string {
	issuer := strings.TrimSpace(os.Getenv("OTP_ISSUER"))
	if issuer == "" {
		issuer = strings.TrimSpace(os.Getenv("PASSKEY_RP_DISPLAY_NAME"))
	}
	if issuer == "" {
		issuer = "Auth"
	}
	return issuer
}

func otpAuthURL(issuer, account, secret string) string {
	query := url.Values{
		"secret":    {secret},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {"6"},
		"period":    {"30"},
	}
	return (&url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: query.Encode(),
	}).String()
}
