package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/auth/internal/secretbox"
	"github.com/iautre/auth/pkg/constant"
	"github.com/iautre/auth/pkg/dto"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/oauth2"
)

const (
	federatedSessionTTL = 10 * time.Minute
	federatedDiscovery  = 10 * time.Second
)

// 第三方 OIDC 登录相关的可判别错误。
var (
	ErrFederatedProviderNotFound   = errors.New("第三方登录方式不存在")
	ErrFederatedProviderDisabled   = errors.New("第三方登录方式已停用")
	ErrFederatedStateInvalid       = errors.New("登录会话已失效，请重新发起")
	ErrFederatedRegistrationClosed = errors.New("该登录方式未开放自助注册")
	ErrInvalidReturnTo             = errors.New("return_to 必须是站内相对路径")
)

// federatedProvider 是 discovery 之后的运行时配置，按 name 缓存。
type federatedProvider struct {
	name         string
	label        string
	issuer       string
	autoRegister bool
	oauth        oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

var (
	federatedMu    sync.Mutex
	federatedCache = make(map[string]*federatedProvider)
)

// FederatedService 让 auth 作为 OIDC 依赖方（RP）接入多个第三方 provider。
type FederatedService struct {
	BaseService
}

// InvalidateFederatedProviderCache 在配置变更后清掉单个 provider 的缓存。
func InvalidateFederatedProviderCache(name string) {
	federatedMu.Lock()
	defer federatedMu.Unlock()
	delete(federatedCache, name)
}

// CallbackPath 是某个 provider 的回调路径，管理页面要把它显示给管理员去第三方登记。
func CallbackPath(name string) string {
	return "/federated/" + name + "/callback"
}

// CallbackURL 是回调的完整地址。
func CallbackURL(name string) string {
	base := strings.TrimSuffix(strings.TrimSpace(gowk.BaseURL()), "/")
	if base == "" {
		return CallbackPath(name)
	}
	return base + CallbackPath(name)
}

// PublicProviders 返回登录页需要的按钮列表，不含任何密钥。
func (s *FederatedService) PublicProviders(ctx context.Context) ([]dto.PublicIdentityProvider, error) {
	rows, err := s.getQueries(ctx).ListPublicIdentityProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]dto.PublicIdentityProvider, 0, len(rows))
	for _, row := range rows {
		out = append(out, dto.PublicIdentityProvider{Name: row.Name, Label: row.Label})
	}
	return out, nil
}

// BeginLogin 生成 state / nonce / PKCE 并把用户重定向到第三方授权端点。
func (s *FederatedService) BeginLogin(ctx context.Context, name, returnTo string) (string, error) {
	provider, err := s.provider(ctx, name)
	if err != nil {
		return "", err
	}

	returnTo, err = sanitizeReturnTo(returnTo)
	if err != nil {
		return "", err
	}

	state := randomToken(32)
	nonce := randomToken(32)
	verifier := randomToken(48)

	if err := s.getQueries(ctx).InsertFederatedSession(ctx, db2.InsertFederatedSessionParams{
		StateHash:    hashState(state),
		Provider:     name,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ReturnTo:     pgtype.Text{String: returnTo, Valid: returnTo != ""},
		Expires:      pgtype.Timestamptz{Time: time.Now().Add(federatedSessionTTL), Valid: true},
	}); err != nil {
		return "", err
	}

	return provider.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

// CompleteLogin 处理回调：校验 state、换 token、验签 id_token，然后解析出本地用户。
// 返回的 returnTo 是发起登录时带的站内路径，调用方负责种 cookie 后跳回去。
func (s *FederatedService) CompleteLogin(ctx context.Context, name, code, state string) (db2.AuthUser, string, error) {
	queries := s.getQueries(ctx)

	session, err := queries.FederatedSessionByState(ctx, hashState(state))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db2.AuthUser{}, "", ErrFederatedStateInvalid
		}
		return db2.AuthUser{}, "", err
	}
	// 一次性消费：无论后续成败都删掉，防止重放。
	if err := queries.DeleteFederatedSession(ctx, session.StateHash); err != nil {
		return db2.AuthUser{}, "", err
	}

	if session.Provider != name {
		return db2.AuthUser{}, "", ErrFederatedStateInvalid
	}
	if time.Now().After(session.Expires.Time) {
		return db2.AuthUser{}, "", ErrFederatedStateInvalid
	}

	provider, err := s.provider(ctx, name)
	if err != nil {
		return db2.AuthUser{}, "", err
	}

	token, err := provider.oauth.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", session.CodeVerifier))
	if err != nil {
		return db2.AuthUser{}, "", fmt.Errorf("向第三方换取 token 失败: %w", err)
	}

	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return db2.AuthUser{}, "", errors.New("第三方未返回 id_token，该 provider 可能不是标准 OIDC")
	}

	idToken, err := provider.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return db2.AuthUser{}, "", fmt.Errorf("id_token 校验失败: %w", err)
	}
	if idToken.Nonce != session.Nonce {
		return db2.AuthUser{}, "", errors.New("id_token nonce 不匹配")
	}

	var claims federatedClaims
	if err := idToken.Claims(&claims); err != nil {
		return db2.AuthUser{}, "", fmt.Errorf("解析 id_token claims 失败: %w", err)
	}
	if claims.Subject == "" {
		return db2.AuthUser{}, "", errors.New("id_token 缺少 sub")
	}

	user, err := s.resolveUser(ctx, provider, claims)
	if err != nil {
		return db2.AuthUser{}, "", err
	}
	return user, session.ReturnTo.String, nil
}

type federatedClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
}

// resolveUser 把外部身份落到本地用户：
// 已绑定直接返回；未绑定则按 email_verified 决定合并到已有账号，否则按开关新建。
func (s *FederatedService) resolveUser(ctx context.Context, provider *federatedProvider, claims federatedClaims) (db2.AuthUser, error) {
	queries := s.getQueries(ctx)

	identity, err := queries.IdentityByProviderSubject(ctx, db2.IdentityByProviderSubjectParams{
		Provider: provider.name,
		Subject:  claims.Subject,
	})
	if err == nil {
		user, err := queries.UserById(ctx, identity.UserID)
		if err != nil {
			return db2.AuthUser{}, err
		}
		if !user.Enabled {
			return db2.AuthUser{}, ErrAccountDisabled
		}
		return user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return db2.AuthUser{}, err
	}

	var user db2.AuthUser
	merged := false

	// 只有第三方明确声明邮箱已验证时才允许合并到同邮箱的已有账号，
	// 否则任何人都能用一个未验证邮箱接管别人的账号。
	if claims.Email != "" && claims.EmailVerified {
		existing, err := queries.UserByEmail(ctx, claims.Email)
		switch {
		case err == nil:
			user = existing
			merged = true
		case errors.Is(err, pgx.ErrNoRows):
			// 继续走新建
		default:
			return db2.AuthUser{}, err
		}
	}

	if !merged {
		if !provider.autoRegister {
			return db2.AuthUser{}, ErrFederatedRegistrationClosed
		}
		created, err := s.createFederatedUser(ctx, claims)
		if err != nil {
			return db2.AuthUser{}, err
		}
		user = created
	}

	if !user.Enabled {
		return db2.AuthUser{}, ErrAccountDisabled
	}

	var identityService IdentityService
	if _, err := identityService.Link(ctx, user.ID, provider.name, provider.issuer, claims.Subject,
		claims.Email, claims.EmailVerified, displayNameOf(claims), claims.Picture); err != nil {
		return db2.AuthUser{}, err
	}
	return user, nil
}

func (s *FederatedService) createFederatedUser(ctx context.Context, claims federatedClaims) (db2.AuthUser, error) {
	nickname := displayNameOf(claims)
	if nickname == "" {
		nickname = maskTarget(ChannelEmail, claims.Email)
	}
	if nickname == "" {
		nickname = "用户"
	}

	params := db2.CreateUserParams{
		Nickname:   pgtype.Text{String: nickname, Valid: true},
		Group:      pgtype.Text{String: constant.USER_GROUP_DEFAULT, Valid: true},
		IsVerified: pgtype.Bool{Bool: claims.EmailVerified, Valid: true},
	}
	if claims.Email != "" {
		params.Email = pgtype.Text{String: claims.Email, Valid: true}
	}

	user, err := s.getQueries(ctx).CreateUser(ctx, params)
	if err != nil {
		return db2.AuthUser{}, friendlyUniqueViolation(err)
	}
	return user, nil
}

// provider 按 name 取运行时配置，命中缓存直接返回。
func (s *FederatedService) provider(ctx context.Context, name string) (*federatedProvider, error) {
	federatedMu.Lock()
	defer federatedMu.Unlock()

	if cached, ok := federatedCache[name]; ok {
		return cached, nil
	}

	record, err := s.getQueries(ctx).IdentityProviderByName(ctx, name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFederatedProviderNotFound
		}
		return nil, err
	}
	if !record.Enabled {
		return nil, ErrFederatedProviderDisabled
	}

	secret, err := secretbox.Open(record.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("解密 %s 的 client_secret 失败: %w", name, err)
	}

	// discovery 用独立超时，不受当前请求取消影响，否则一次断连会把失败结果留在缓存外反复重试。
	discoveryCtx, cancel := context.WithTimeout(context.Background(), federatedDiscovery)
	defer cancel()

	oidcProvider, err := oidc.NewProvider(discoveryCtx, record.Issuer)
	if err != nil {
		return nil, fmt.Errorf("发现 %s 的 OIDC 配置失败: %w", record.Issuer, err)
	}

	provider := &federatedProvider{
		name:         record.Name,
		label:        record.Label,
		issuer:       record.Issuer,
		autoRegister: record.AutoRegister,
		oauth: oauth2.Config{
			ClientID:     record.ClientID,
			ClientSecret: secret,
			Endpoint:     oidcProvider.Endpoint(),
			RedirectURL:  CallbackURL(record.Name),
			Scopes:       splitScopes(record.Scopes),
		},
		verifier: oidcProvider.Verifier(&oidc.Config{ClientID: record.ClientID}),
	}
	federatedCache[name] = provider
	return provider, nil
}

// WarmFederatedProviders 在启动后异步预热已启用的 provider，失败只记日志。
func WarmFederatedProviders() {
	go func() {
		// 挂载发生在数据库迁移之前，等一拍再查表，否则会撞上"表不存在"。
		time.Sleep(5 * time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		rows, err := (&BaseService{}).getQueries(ctx).ListPublicIdentityProviders(ctx)
		if err != nil {
			return
		}
		var service FederatedService
		for _, row := range rows {
			if _, err := service.provider(ctx, row.Name); err != nil {
				slog.Warn("预热第三方登录失败", "provider", row.Name, "err", err)
			}
		}
	}()
}

func splitScopes(raw string) []string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return fields
}

func sanitizeReturnTo(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "", ErrInvalidReturnTo
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "", ErrInvalidReturnTo
	}
	return raw, nil
}

func hashState(state string) string {
	sum := sha256.Sum256([]byte("federated-state:" + state))
	return fmt.Sprintf("%x", sum[:])
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic("service: 生成随机串失败: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func displayNameOf(claims federatedClaims) string {
	if strings.TrimSpace(claims.Name) != "" {
		return strings.TrimSpace(claims.Name)
	}
	return strings.TrimSpace(claims.PreferredUsername)
}
