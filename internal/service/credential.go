package service

import (
	"context"
	"errors"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/gowk"
)

var ErrLastAuthenticationMethod = errors.New("请至少保留一种登录方式（验证码、通行密钥或第三方账号）")

func withLockedUserCredentials(ctx context.Context, userID int64, action func(*db2.Queries) error) error {
	if userID <= 0 {
		return gowk.NewError("invalid user ID")
	}
	tx, err := gowk.DB(ctx).Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	queries := db2.New(tx)
	if _, err := queries.LockUserForCredentialChange(ctx, userID); err != nil {
		return err
	}
	if err := action(queries); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ensureAuthenticationMethodRemains 兜住"不能删掉最后一个登录方式"：
// OTP、通行密钥、第三方身份三类凭据都算；此外手机号/邮箱本身
// 也能接收验证码登录（注册时已验证过所有权），因此同样计入。
func ensureAuthenticationMethodRemains(ctx context.Context, queries *db2.Queries, userID int64) error {
	user, err := queries.UserById(ctx, userID)
	if err != nil {
		return err
	}
	if user.Phone.String != "" || user.Email.String != "" {
		return nil
	}

	otpCount, err := queries.CountOtpCredentialsByUser(ctx, userID)
	if err != nil {
		return err
	}
	passkeyCount, err := queries.CountPasskeyCredentialsByUser(ctx, userID)
	if err != nil {
		return err
	}
	identityCount, err := queries.CountIdentitiesByUser(ctx, userID)
	if err != nil {
		return err
	}
	if !authenticationMethodRemains(otpCount, passkeyCount, identityCount) {
		return ErrLastAuthenticationMethod
	}
	return nil
}

// authenticationMethodRemains 三类凭据任一计数大于 0 即认为还留有登录方式。
func authenticationMethodRemains(otpCount, passkeyCount, identityCount int64) bool {
	return otpCount > 0 || passkeyCount > 0 || identityCount > 0
}
