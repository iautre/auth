package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	db2 "github.com/iautre/auth/internal/db"
	"github.com/iautre/gowk"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/go-webauthn/webauthn/protocol"
	webauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
)

const (
	passkeyChallengeTTL    = 5 * time.Minute
	passkeyPurposeRegister = "register"
	passkeyPurposeLogin    = "login"
	passkeyNameMaxLength   = 50
)

type PasskeyService struct {
	BaseService
}

type PasskeyBeginResult struct {
	Options   any    `json:"options"`
	FlowToken string `json:"flow_token"`
	ExpiresAt int64  `json:"expires_at"`
}

type PasskeyCredentialSummary struct {
	ID             int64             `json:"id"`
	Name           string            `json:"name"`
	DeviceInfo     PasskeyDeviceInfo `json:"device_info"`
	Transports     []string          `json:"transports"`
	Attachment     string            `json:"attachment"`
	BackupEligible bool              `json:"backup_eligible"`
	BackupState    bool              `json:"backup_state"`
	LastUsedAt     *time.Time        `json:"last_used_at"`
	Created        time.Time         `json:"created"`
}

type PasskeyDeviceInfo struct {
	UserAgent       string `json:"user_agent,omitempty"`
	Platform        string `json:"platform,omitempty"`
	PlatformVersion string `json:"platform_version,omitempty"`
	Model           string `json:"model,omitempty"`
	Mobile          bool   `json:"mobile"`
}

type passkeyUser struct {
	user        db2.AuthUser
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte {
	return []byte(strconv.FormatInt(u.user.ID, 10))
}

func (u *passkeyUser) WebAuthnName() string {
	if u.user.Email.Valid && strings.TrimSpace(u.user.Email.String) != "" {
		return strings.TrimSpace(u.user.Email.String)
	}
	if u.user.Phone.Valid && strings.TrimSpace(u.user.Phone.String) != "" {
		return strings.TrimSpace(u.user.Phone.String)
	}
	return fmt.Sprintf("user-%d", u.user.ID)
}

func (u *passkeyUser) WebAuthnDisplayName() string {
	if u.user.Nickname.Valid && strings.TrimSpace(u.user.Nickname.String) != "" {
		return strings.TrimSpace(u.user.Nickname.String)
	}
	return u.WebAuthnName()
}

func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (s *PasskeyService) Status(ctx context.Context, userID int64) (bool, error) {
	credentials, err := s.getQueries(ctx).ListPasskeyCredentialsByUser(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(credentials) > 0, nil
}

func (s *PasskeyService) ListCredentials(ctx context.Context, userID int64) ([]PasskeyCredentialSummary, error) {
	if userID <= 0 {
		return nil, gowk.NewError("invalid user ID")
	}
	records, err := s.getQueries(ctx).ListPasskeyCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list passkey credentials: %w", err)
	}
	credentials := make([]PasskeyCredentialSummary, 0, len(records))
	for _, record := range records {
		credential, err := passkeyCredentialSummary(record)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, nil
}

func (s *PasskeyService) DeleteCredential(ctx context.Context, userID, credentialID int64) (bool, error) {
	if userID <= 0 || credentialID <= 0 {
		return false, gowk.NewError("invalid passkey credential")
	}
	deleted := false
	err := withLockedUserCredentials(ctx, userID, func(queries *db2.Queries) error {
		rows, err := queries.DeletePasskeyCredentialByUser(ctx, db2.DeletePasskeyCredentialByUserParams{
			ID: credentialID, UserID: userID,
		})
		deleted = rows == 1
		if err != nil || !deleted {
			return err
		}
		return ensureAuthenticationMethodRemains(ctx, queries, userID)
	})
	if err != nil {
		return false, fmt.Errorf("delete passkey credential: %w", err)
	}
	return deleted, nil
}

func (s *PasskeyService) UpdateCredentialName(ctx context.Context, userID, credentialID int64, name string) (PasskeyCredentialSummary, bool, error) {
	name = strings.TrimSpace(name)
	if userID <= 0 || credentialID <= 0 || name == "" {
		return PasskeyCredentialSummary{}, false, gowk.NewError("请填写通行密钥名称")
	}
	if len([]rune(name)) > passkeyNameMaxLength {
		return PasskeyCredentialSummary{}, false, gowk.NewError("通行密钥名称不能超过 50 个字符")
	}
	record, err := s.getQueries(ctx).UpdatePasskeyCredentialName(ctx, db2.UpdatePasskeyCredentialNameParams{
		ID: credentialID, UserID: userID, Name: name,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PasskeyCredentialSummary{}, false, nil
	}
	if err != nil {
		return PasskeyCredentialSummary{}, false, fmt.Errorf("update passkey credential name: %w", err)
	}
	summary, err := passkeyCredentialSummary(record)
	if err != nil {
		return PasskeyCredentialSummary{}, false, err
	}
	return summary, true, nil
}

func (s *PasskeyService) BeginRegistration(ctx context.Context, userID int64) (*PasskeyBeginResult, error) {
	user, wrapper, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	wa, err := newWebAuthn()
	if err != nil {
		return nil, err
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(wrapper.credentials))
	for _, credential := range wrapper.credentials {
		exclusions = append(exclusions, credential.Descriptor())
	}
	options := make([]webauthn.RegistrationOption, 0, 1)
	if len(exclusions) > 0 {
		options = append(options, webauthn.WithExclusions(exclusions))
	}
	creation, session, err := wa.BeginRegistration(wrapper, options...)
	if err != nil {
		return nil, err
	}
	flowToken, expiresAt, err := s.storeChallenge(ctx, passkeyPurposeRegister, user.ID, session)
	if err != nil {
		return nil, err
	}
	return &PasskeyBeginResult{Options: creation, FlowToken: flowToken, ExpiresAt: expiresAt.Unix()}, nil
}

func (s *PasskeyService) FinishRegistration(ctx context.Context, userID int64, flowToken string, credentialJSON []byte, deviceInfo PasskeyDeviceInfo) (PasskeyCredentialSummary, error) {
	if userID <= 0 || flowToken == "" || len(credentialJSON) == 0 {
		return PasskeyCredentialSummary{}, gowk.NewError("invalid passkey registration request")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(credentialJSON)
	if err != nil {
		return PasskeyCredentialSummary{}, fmt.Errorf("parse passkey registration response: %w", err)
	}
	session, challengeUserID, err := s.consumeChallenge(ctx, flowToken, passkeyPurposeRegister)
	if err != nil {
		return PasskeyCredentialSummary{}, err
	}
	if challengeUserID != userID {
		return PasskeyCredentialSummary{}, gowk.NewError("passkey registration user mismatch")
	}
	_, wrapper, err := s.loadUser(ctx, userID)
	if err != nil {
		return PasskeyCredentialSummary{}, err
	}
	wa, err := newWebAuthn()
	if err != nil {
		return PasskeyCredentialSummary{}, err
	}
	credential, err := wa.CreateCredential(wrapper, *session, parsed)
	if err != nil {
		return PasskeyCredentialSummary{}, fmt.Errorf("validate passkey registration: %w", err)
	}
	transports, err := json.Marshal(credential.Transport)
	if err != nil {
		return PasskeyCredentialSummary{}, fmt.Errorf("encode passkey transports: %w", err)
	}
	encodedDeviceInfo, err := json.Marshal(normalizePasskeyDeviceInfo(deviceInfo))
	if err != nil {
		return PasskeyCredentialSummary{}, fmt.Errorf("encode passkey device info: %w", err)
	}
	record, err := s.getQueries(ctx).CreatePasskeyCredential(ctx, db2.CreatePasskeyCredentialParams{
		UserID:          userID,
		DeviceInfo:      encodedDeviceInfo,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transports:      string(transports),
		Aaguid:          credential.Authenticator.AAGUID,
		SignCount:       int64(credential.Authenticator.SignCount),
		CloneWarning:    credential.Authenticator.CloneWarning,
		UserPresent:     credential.Flags.UserPresent,
		UserVerified:    credential.Flags.UserVerified,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		Attachment:      string(credential.Authenticator.Attachment),
	})
	if err != nil {
		return PasskeyCredentialSummary{}, fmt.Errorf("store passkey credential: %w", err)
	}
	return passkeyCredentialSummary(record)
}

func (s *PasskeyService) BeginLogin(ctx context.Context) (*PasskeyBeginResult, error) {
	wa, err := newWebAuthn()
	if err != nil {
		return nil, err
	}
	assertion, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, err
	}
	flowToken, expiresAt, err := s.storeChallenge(ctx, passkeyPurposeLogin, 0, session)
	if err != nil {
		return nil, err
	}
	return &PasskeyBeginResult{Options: assertion, FlowToken: flowToken, ExpiresAt: expiresAt.Unix()}, nil
}

func (s *PasskeyService) FinishLogin(ctx context.Context, flowToken string, credentialJSON []byte) (db2.AuthUser, error) {
	if flowToken == "" || len(credentialJSON) == 0 {
		return db2.AuthUser{}, gowk.NewError("invalid passkey login request")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return db2.AuthUser{}, fmt.Errorf("parse passkey login response: %w", err)
	}
	session, _, err := s.consumeChallenge(ctx, flowToken, passkeyPurposeLogin)
	if err != nil {
		return db2.AuthUser{}, err
	}
	wa, err := newWebAuthn()
	if err != nil {
		return db2.AuthUser{}, err
	}
	var authenticatedUser db2.AuthUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		record, err := s.getQueries(ctx).GetPasskeyCredentialByID(ctx, rawID)
		if err != nil {
			return nil, gowk.NewError("passkey credential not found")
		}
		user, wrapper, err := s.loadUser(ctx, record.UserID)
		if err != nil {
			return nil, err
		}
		if len(userHandle) > 0 && string(userHandle) != strconv.FormatInt(user.ID, 10) {
			return nil, gowk.NewError("passkey user handle mismatch")
		}
		authenticatedUser = user
		return wrapper, nil
	}
	_, credential, err := wa.ValidatePasskeyLogin(handler, *session, parsed)
	if err != nil {
		return db2.AuthUser{}, fmt.Errorf("validate passkey login: %w", err)
	}
	if authenticatedUser.ID <= 0 || !authenticatedUser.Enabled {
		return db2.AuthUser{}, gowk.NewError("account is disabled")
	}
	rows, err := s.getQueries(ctx).UpdatePasskeyCredentialAfterAssertion(ctx, db2.UpdatePasskeyCredentialAfterAssertionParams{
		UserID:         authenticatedUser.ID,
		CredentialID:   credential.ID,
		SignCount:      int64(credential.Authenticator.SignCount),
		CloneWarning:   credential.Authenticator.CloneWarning,
		UserPresent:    credential.Flags.UserPresent,
		UserVerified:   credential.Flags.UserVerified,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	})
	if err != nil {
		return db2.AuthUser{}, fmt.Errorf("update passkey credential: %w", err)
	}
	if rows != 1 {
		return db2.AuthUser{}, gowk.NewError("passkey credential not found")
	}
	var userService UserService
	if err := userService.UpdateLoginInfo(ctx, authenticatedUser.ID); err != nil {
		slog.WarnContext(ctx, "update passkey login info failed", "user_id", authenticatedUser.ID, "err", err)
	}
	return authenticatedUser, nil
}

func (s *PasskeyService) loadUser(ctx context.Context, userID int64) (db2.AuthUser, *passkeyUser, error) {
	var userService UserService
	user, err := userService.GetById(ctx, userID)
	if err != nil {
		return db2.AuthUser{}, nil, err
	}
	if !user.Enabled {
		return db2.AuthUser{}, nil, gowk.NewError("account is disabled")
	}
	records, err := s.getQueries(ctx).ListPasskeyCredentialsByUser(ctx, userID)
	if err != nil {
		return db2.AuthUser{}, nil, err
	}
	credentials := make([]webauthn.Credential, 0, len(records))
	for _, record := range records {
		credential, err := passkeyCredential(record)
		if err != nil {
			return db2.AuthUser{}, nil, err
		}
		credentials = append(credentials, credential)
	}
	return user, &passkeyUser{user: user, credentials: credentials}, nil
}

func passkeyCredential(record db2.AuthPasskeyCredential) (webauthn.Credential, error) {
	if record.SignCount < 0 || record.SignCount > math.MaxUint32 {
		return webauthn.Credential{}, gowk.NewError("invalid passkey sign count")
	}
	var transportNames []string
	if err := json.Unmarshal([]byte(record.Transports), &transportNames); err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode passkey transports: %w", err)
	}
	transports := make([]protocol.AuthenticatorTransport, 0, len(transportNames))
	for _, transport := range transportNames {
		transports = append(transports, protocol.AuthenticatorTransport(transport))
	}
	return webauthn.Credential{
		ID:              record.CredentialID,
		PublicKey:       record.PublicKey,
		AttestationType: record.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    record.UserPresent,
			UserVerified:   record.UserVerified,
			BackupEligible: record.BackupEligible,
			BackupState:    record.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       record.Aaguid,
			SignCount:    uint32(record.SignCount),
			CloneWarning: record.CloneWarning,
			Attachment:   protocol.AuthenticatorAttachment(record.Attachment),
		},
	}, nil
}

func passkeyCredentialSummary(record db2.AuthPasskeyCredential) (PasskeyCredentialSummary, error) {
	var transports []string
	if err := json.Unmarshal([]byte(record.Transports), &transports); err != nil {
		return PasskeyCredentialSummary{}, fmt.Errorf("decode passkey transports: %w", err)
	}
	if transports == nil {
		transports = []string{}
	}
	var lastUsedAt *time.Time
	if record.LastUsedAt.Valid {
		value := record.LastUsedAt.Time
		lastUsedAt = &value
	}
	var deviceInfo PasskeyDeviceInfo
	if len(record.DeviceInfo) > 0 {
		if err := json.Unmarshal(record.DeviceInfo, &deviceInfo); err != nil {
			return PasskeyCredentialSummary{}, fmt.Errorf("decode passkey device info: %w", err)
		}
	}
	return PasskeyCredentialSummary{
		ID:             record.ID,
		Name:           record.Name,
		DeviceInfo:     deviceInfo,
		Transports:     transports,
		Attachment:     record.Attachment,
		BackupEligible: record.BackupEligible,
		BackupState:    record.BackupState,
		LastUsedAt:     lastUsedAt,
		Created:        record.Created.Time,
	}, nil
}

func normalizePasskeyDeviceInfo(info PasskeyDeviceInfo) PasskeyDeviceInfo {
	info.UserAgent = truncateRunes(strings.TrimSpace(info.UserAgent), 512)
	info.Platform = truncateRunes(strings.TrimSpace(info.Platform), 100)
	info.PlatformVersion = truncateRunes(strings.TrimSpace(info.PlatformVersion), 100)
	info.Model = truncateRunes(strings.TrimSpace(info.Model), 100)
	return info
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func (s *PasskeyService) storeChallenge(ctx context.Context, purpose string, userID int64, session *webauthn.SessionData) (string, time.Time, error) {
	if session == nil {
		return "", time.Time{}, gowk.NewError("passkey session is empty")
	}
	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encode passkey session: %w", err)
	}
	token := gowk.GenerateRandomString(32)
	expires := time.Now().Add(passkeyChallengeTTL)
	params := db2.CreatePasskeyChallengeParams{
		Token:       token,
		Purpose:     purpose,
		SessionData: sessionData,
		Expires:     pgtype.Timestamptz{Time: expires, Valid: true},
	}
	if userID > 0 {
		params.UserID = pgtype.Int8{Int64: userID, Valid: true}
	}
	if err := s.getQueries(ctx).CreatePasskeyChallenge(ctx, params); err != nil {
		return "", time.Time{}, fmt.Errorf("store passkey challenge: %w", err)
	}
	_, _ = s.getQueries(ctx).DeleteExpiredPasskeyChallenges(ctx)
	return token, expires, nil
}

func (s *PasskeyService) consumeChallenge(ctx context.Context, token, purpose string) (*webauthn.SessionData, int64, error) {
	record, err := s.getQueries(ctx).ConsumePasskeyChallenge(ctx, db2.ConsumePasskeyChallengeParams{Token: token, Purpose: purpose})
	if err != nil {
		return nil, 0, gowk.NewError("passkey challenge is invalid or expired")
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(record.SessionData, &session); err != nil {
		return nil, 0, fmt.Errorf("decode passkey session: %w", err)
	}
	if record.UserID.Valid {
		return &session, record.UserID.Int64, nil
	}
	return &session, 0, nil
}

func newWebAuthn() (*webauthn.WebAuthn, error) {
	config, err := passkeyConfig()
	if err != nil {
		return nil, err
	}
	return webauthn.New(config)
}

func passkeyConfig() (*webauthn.Config, error) {
	origins, err := passkeyOrigins()
	if err != nil {
		return nil, err
	}
	rpID := strings.TrimSpace(os.Getenv("PASSKEY_RP_ID"))
	if rpID == "" {
		parsed, err := url.Parse(origins[0])
		if err != nil {
			return nil, fmt.Errorf("parse passkey origin: %w", err)
		}
		rpID = parsed.Hostname()
	}
	if host, _, err := net.SplitHostPort(rpID); err == nil {
		rpID = host
	}
	if rpID == "" {
		return nil, errors.New("PASSKEY_RP_ID is empty")
	}
	displayName := strings.TrimSpace(os.Getenv("PASSKEY_RP_DISPLAY_NAME"))
	if displayName == "" {
		displayName = "Auth"
	}
	return &webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
		},
	}, nil
}

func passkeyOrigins() ([]string, error) {
	raw := strings.TrimSpace(os.Getenv("PASSKEY_ORIGINS"))
	if raw == "" {
		raw = gowk.BaseURL()
	}
	origins := make([]string, 0, 1)
	for _, value := range strings.Split(raw, ",") {
		parsed, err := url.Parse(strings.TrimSpace(value))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("invalid passkey origin %q", value)
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")) {
			return nil, fmt.Errorf("passkey origin must use HTTPS: %s", value)
		}
		origins = append(origins, parsed.Scheme+"://"+parsed.Host)
	}
	if len(origins) == 0 {
		return nil, errors.New("PASSKEY_ORIGINS is empty")
	}
	return origins, nil
}

func ValidateBrowserOrigin(raw string) error {
	origin := strings.TrimSpace(raw)
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return gowk.NewError("invalid request origin")
	}
	allowedOrigins, err := passkeyOrigins()
	if err != nil {
		return err
	}
	normalized := parsed.Scheme + "://" + parsed.Host
	for _, allowed := range allowedOrigins {
		if strings.EqualFold(normalized, allowed) {
			return nil
		}
	}
	return gowk.NewError("request origin is not allowed")
}
