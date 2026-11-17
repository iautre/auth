package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/internal/secretbox"
	"github.com/iautre/auth/pkg/dto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// providerNamePattern 与数据库 CHECK 约束保持一致。
var providerNamePattern = regexp.MustCompile(`^[a-z0-9_-]{2,32}$`)

var (
	ErrProviderNameInvalid  = errors.New("标识只能是小写字母、数字、下划线和连字符，长度 2-32")
	ErrProviderIssuerBad    = errors.New("issuer 必须是 http(s) 地址")
	ErrProviderSecretNeeded = errors.New("首次创建必须填写 client_secret")
	ErrProviderInUse        = errors.New("该登录方式仍有用户绑定，请先让用户解绑或停用它")
)

// IdentityProviderService 维护第三方 OIDC provider 的配置。
type IdentityProviderService struct {
	BaseService
}

// List 返回管理侧列表，密钥只暴露"是否已配置"。
func (s *IdentityProviderService) List(ctx context.Context) ([]dto.IdentityProviderRes, error) {
	rows, err := s.getQueries(ctx).ListIdentityProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]dto.IdentityProviderRes, 0, len(rows))
	for _, row := range rows {
		out = append(out, identityProviderResponse(row))
	}
	return out, nil
}

// Create 新增一个 provider。name 创建后不可修改，因为 auth_identity 存的就是它。
func (s *IdentityProviderService) Create(ctx context.Context, params *dto.IdentityProviderParams) (dto.IdentityProviderRes, error) {
	name := strings.TrimSpace(params.Name)
	if !providerNamePattern.MatchString(name) {
		return dto.IdentityProviderRes{}, ErrProviderNameInvalid
	}
	issuer, err := normalizeIssuer(params.Issuer)
	if err != nil {
		return dto.IdentityProviderRes{}, err
	}
	if strings.TrimSpace(params.ClientSecret) == "" {
		return dto.IdentityProviderRes{}, ErrProviderSecretNeeded
	}

	sealed, err := secretbox.Seal(params.ClientSecret)
	if err != nil {
		return dto.IdentityProviderRes{}, err
	}

	record, err := s.getQueries(ctx).CreateIdentityProvider(ctx, db2.CreateIdentityProviderParams{
		Name:         name,
		Label:        strings.TrimSpace(params.Label),
		Issuer:       issuer,
		ClientID:     strings.TrimSpace(params.ClientID),
		ClientSecret: sealed,
		Scopes:       normalizeScopes(params.Scopes),
		AutoRegister: boolOr(params.AutoRegister, true),
		Enabled:      boolOr(params.Enabled, true),
	})
	if err != nil {
		if strings.Contains(err.Error(), "auth_identity_provider_name_key") {
			return dto.IdentityProviderRes{}, errors.New("标识已被占用")
		}
		return dto.IdentityProviderRes{}, err
	}

	InvalidateFederatedProviderCache(name)
	return identityProviderResponse(record), nil
}

// Update 修改配置。name 不可改；client_secret 留空表示保持原值。
func (s *IdentityProviderService) Update(ctx context.Context, id int64, params *dto.IdentityProviderParams) (dto.IdentityProviderRes, error) {
	queries := s.getQueries(ctx)

	current, err := queries.IdentityProviderById(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dto.IdentityProviderRes{}, ErrFederatedProviderNotFound
		}
		return dto.IdentityProviderRes{}, err
	}

	issuer, err := normalizeIssuer(params.Issuer)
	if err != nil {
		return dto.IdentityProviderRes{}, err
	}

	secret := current.ClientSecret
	if trimmed := strings.TrimSpace(params.ClientSecret); trimmed != "" && !secretbox.IsSealed(trimmed) {
		sealed, err := secretbox.Seal(trimmed)
		if err != nil {
			return dto.IdentityProviderRes{}, err
		}
		secret = sealed
	}

	record, err := queries.UpdateIdentityProvider(ctx, db2.UpdateIdentityProviderParams{
		ID:           id,
		Label:        strings.TrimSpace(params.Label),
		Issuer:       issuer,
		ClientID:     strings.TrimSpace(params.ClientID),
		ClientSecret: secret,
		Scopes:       normalizeScopes(params.Scopes),
		AutoRegister: boolOr(params.AutoRegister, current.AutoRegister),
		Enabled:      boolOr(params.Enabled, current.Enabled),
	})
	if err != nil {
		return dto.IdentityProviderRes{}, err
	}

	InvalidateFederatedProviderCache(current.Name)
	return identityProviderResponse(record), nil
}

// Delete 物理删除。仍有用户绑定时拒绝，避免把别人的登录方式悄悄删掉。
func (s *IdentityProviderService) Delete(ctx context.Context, id int64) error {
	queries := s.getQueries(ctx)

	current, err := queries.IdentityProviderById(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrFederatedProviderNotFound
		}
		return err
	}

	bound, err := queries.CountIdentitiesByProvider(ctx, current.Name)
	if err != nil {
		return err
	}
	if bound > 0 {
		return fmt.Errorf("%w（%d 个用户）", ErrProviderInUse, bound)
	}

	if _, err := queries.DeleteIdentityProvider(ctx, id); err != nil {
		return err
	}

	InvalidateFederatedProviderCache(current.Name)
	return nil
}

func identityProviderResponse(record db2.AuthIdentityProvider) dto.IdentityProviderRes {
	return dto.IdentityProviderRes{
		ID:           record.ID,
		Name:         record.Name,
		Label:        record.Label,
		Issuer:       record.Issuer,
		ClientID:     record.ClientID,
		SecretSet:    record.ClientSecret != "",
		Scopes:       record.Scopes,
		AutoRegister: record.AutoRegister,
		Enabled:      record.Enabled,
		CallbackURL:  CallbackURL(record.Name),
		Created:      formatTime(record.Created),
		Updated:      formatTime(record.Updated),
	}
}

func normalizeIssuer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", ErrProviderIssuerBad
	}
	return strings.TrimSuffix(raw, "/"), nil
}

func normalizeScopes(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "openid email profile"
	}
	// 去重并强制带上 openid，否则拿不到 id_token。
	seen := map[string]bool{}
	out := make([]string, 0, len(fields)+1)
	for _, field := range append([]string{"openid"}, fields...) {
		if seen[field] {
			continue
		}
		seen[field] = true
		out = append(out, field)
	}
	return strings.Join(out, " ")
}

func boolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func formatTime(ts pgtype.Timestamptz) string {
	if !ts.Valid {
		return ""
	}
	return ts.Time.Format(time.RFC3339)
}
