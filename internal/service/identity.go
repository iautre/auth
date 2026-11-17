package service

import (
	"context"
	"errors"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ErrIdentityNotFound 表示用户没有绑定该 provider。
var ErrIdentityNotFound = errors.New("尚未绑定该第三方账号")

// IdentityService 管理本地用户与第三方身份之间的绑定关系。
type IdentityService struct {
	BaseService
}

// Link 绑定外部身份。同一用户重复绑定同一 provider 时以最新信息覆盖。
func (s *IdentityService) Link(ctx context.Context, userID int64, provider, issuer, subject, email string, emailVerified bool, name, avatar string) (db2.AuthIdentity, error) {
	queries := s.getQueries(ctx)

	existing, err := queries.IdentityByProviderSubject(ctx, db2.IdentityByProviderSubjectParams{
		Provider: provider,
		Subject:  subject,
	})
	switch {
	case err == nil:
		if existing.UserID != userID {
			return db2.AuthIdentity{}, errors.New("该第三方账号已绑定到其他用户")
		}
		return existing, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return db2.AuthIdentity{}, err
	}

	// 同一用户换绑到同一 provider 时先清掉旧记录，保证一个 provider 只有一条。
	if _, err := queries.DeleteIdentityByUserProvider(ctx, db2.DeleteIdentityByUserProviderParams{
		UserID:   userID,
		Provider: provider,
	}); err != nil {
		return db2.AuthIdentity{}, err
	}

	identity, err := queries.InsertIdentity(ctx, db2.InsertIdentityParams{
		UserID:        userID,
		Provider:      provider,
		Issuer:        issuer,
		Subject:       subject,
		Email:         pgtype.Text{String: email, Valid: email != ""},
		EmailVerified: emailVerified,
		DisplayName:   pgtype.Text{String: name, Valid: name != ""},
		Avatar:        pgtype.Text{String: avatar, Valid: avatar != ""},
	})
	if err != nil {
		return db2.AuthIdentity{}, err
	}
	return identity, nil
}

// Unlink 解绑第三方身份；解绑后必须还剩至少一种登录方式。
func (s *IdentityService) Unlink(ctx context.Context, userID int64, provider string) error {
	return withLockedUserCredentials(ctx, userID, func(queries *db2.Queries) error {
		deleted, err := queries.DeleteIdentityByUserProvider(ctx, db2.DeleteIdentityByUserProviderParams{
			UserID:   userID,
			Provider: provider,
		})
		if err != nil {
			return err
		}
		if deleted == 0 {
			return ErrIdentityNotFound
		}
		return ensureAuthenticationMethodRemains(ctx, queries, userID)
	})
}

// List 返回用户已绑定的全部第三方身份。
func (s *IdentityService) List(ctx context.Context, userID int64) ([]db2.AuthIdentity, error) {
	return s.getQueries(ctx).IdentitiesByUser(ctx, userID)
}
