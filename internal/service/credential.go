package service

import (
	"context"
	"errors"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/gowk"
)

var ErrLastAuthenticationMethod = errors.New("OTP 和通行密钥必须至少保留一个")

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

func ensureAuthenticationMethodRemains(ctx context.Context, queries *db2.Queries, userID int64) error {
	otpCount, err := queries.CountOtpCredentialsByUser(ctx, userID)
	if err != nil {
		return err
	}
	passkeyCount, err := queries.CountPasskeyCredentialsByUser(ctx, userID)
	if err != nil {
		return err
	}
	if !authenticationMethodRemains(otpCount, passkeyCount) {
		return ErrLastAuthenticationMethod
	}
	return nil
}

func authenticationMethodRemains(otpCount, passkeyCount int64) bool {
	return otpCount > 0 || passkeyCount > 0
}
