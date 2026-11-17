package oidcclient_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iautre/auth/pkg/oidcclient"
)

const testKID = "test-key-1"

// fakeProvider 是最小可用的 OIDC 服务端：discovery、jwks、token、userinfo。
type fakeProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	issuer string

	mu            sync.Mutex
	lastTokenForm url.Values
	lastTokenAuth string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	f := &fakeProvider{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                f.issuer,
			"authorization_endpoint":                f.issuer + "/oauth2/authorize",
			"token_endpoint":                        f.issuer + "/oauth2/token",
			"userinfo_endpoint":                     f.issuer + "/oidc/userinfo",
			"jwks_uri":                              f.issuer + "/oidc/jwks",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/oidc/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := key.PublicKey
		writeJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": testKID,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		f.lastTokenForm = r.PostForm
		f.lastTokenAuth = r.Header.Get("Authorization")
		f.mu.Unlock()

		if clientID, _, ok := r.BasicAuth(); !ok || clientID != "console" {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}

		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			if r.PostForm.Get("code") != "good-code" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_grant")
				return
			}
			if r.PostForm.Get("code_verifier") == "" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request")
				return
			}
		case "refresh_token":
			if r.PostForm.Get("refresh_token") != "refresh-1" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_grant")
				return
			}
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type")
			return
		}

		accessToken := "access-1"
		refreshToken := "refresh-1"
		nonce := "nonce-1"
		if r.PostForm.Get("grant_type") == "refresh_token" {
			accessToken = "access-2"
			refreshToken = "refresh-2"
			nonce = ""
		}

		claims := map[string]any{
			"iss":                   f.issuer,
			"sub":                   "42",
			"aud":                   "console",
			"exp":                   time.Now().Add(time.Hour).Unix(),
			"iat":                   time.Now().Unix(),
			"name":                  "李四",
			"preferred_username":    "lisi",
			"email":                 "lisi@example.com",
			"email_verified":        true,
			"phone_number":          "13800138000",
			"phone_number_verified": false,
		}
		if nonce != "" {
			claims["nonce"] = nonce
		}

		writeJSON(w, map[string]any{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": refreshToken,
			"scope":         "openid profile email phone",
			"id_token":      f.sign(t, claims),
		})
	})
	mux.HandleFunc("/oidc/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-1" {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		writeJSON(w, map[string]any{
			"sub":            "42",
			"name":           "李四",
			"email":          "lisi@example.com",
			"email_verified": true,
		})
	})

	f.server = httptest.NewServer(mux)
	f.issuer = f.server.URL
	return f
}

func (f *fakeProvider) Close() { f.server.Close() }

func (f *fakeProvider) sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": testKID})
	if err != nil {
		t.Fatalf("序列化 header 失败: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("序列化 claims 失败: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func writeOAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func newClient(t *testing.T, f *fakeProvider) *oidcclient.Client {
	t.Helper()
	client, err := oidcclient.New(context.Background(), oidcclient.Config{
		Issuer:       f.issuer,
		ClientID:     "console",
		ClientSecret: "s3cret",
		RedirectURL:  "https://console.example.com/auth/callback",
	})
	if err != nil {
		t.Fatalf("构建客户端失败: %v", err)
	}
	return client
}

func TestEndpointsComeFromDiscovery(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	endpoints := client.Endpoints()

	if endpoints.Issuer != f.issuer {
		t.Errorf("Issuer = %q, want %q", endpoints.Issuer, f.issuer)
	}
	if endpoints.Authorization != f.issuer+"/oauth2/authorize" {
		t.Errorf("Authorization = %q", endpoints.Authorization)
	}
	if endpoints.Token != f.issuer+"/oauth2/token" {
		t.Errorf("Token = %q", endpoints.Token)
	}
	if endpoints.UserInfo != f.issuer+"/oidc/userinfo" {
		t.Errorf("UserInfo = %q", endpoints.UserInfo)
	}
	if endpoints.JWKS != f.issuer+"/oidc/jwks" {
		t.Errorf("JWKS = %q", endpoints.JWKS)
	}
}

func TestAuthCodeURLIncludesPKCEAndNonce(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	authURL, verifier := client.AuthCodeURL("state-abc", oidcclient.AuthURLOptions{Nonce: "nonce-1"})

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("授权地址无法解析: %v", err)
	}
	query := parsed.Query()
	if parsed.Path != "/oauth2/authorize" {
		t.Errorf("path = %q", parsed.Path)
	}
	if query.Get("state") != "state-abc" {
		t.Errorf("state = %q", query.Get("state"))
	}
	if query.Get("nonce") != "nonce-1" {
		t.Errorf("nonce = %q", query.Get("nonce"))
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", query.Get("code_challenge_method"))
	}
	if query.Get("code_challenge") == "" {
		t.Error("缺少 code_challenge")
	}
	if verifier == "" {
		t.Error("PKCE verifier 为空")
	}
	if query.Get("scope") != "openid profile email" {
		t.Errorf("scope = %q", query.Get("scope"))
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	ctx := context.Background()

	_, verifier := client.AuthCodeURL("state-abc", oidcclient.AuthURLOptions{Nonce: "nonce-1"})

	token, err := client.Exchange(ctx, "good-code", verifier)
	if err != nil {
		t.Fatalf("换取 token 失败: %v", err)
	}
	if token.AccessToken != "access-1" || token.RefreshToken != "refresh-1" {
		t.Fatalf("token = %+v", token)
	}
	if token.IDToken == "" {
		t.Fatal("缺少 id_token")
	}
	if token.Expired() {
		t.Error("新签发的 token 不应判定为过期")
	}

	f.mu.Lock()
	form := f.lastTokenForm
	basic := f.lastTokenAuth
	f.mu.Unlock()
	if form.Get("code_verifier") != verifier {
		t.Errorf("code_verifier = %q, want %q", form.Get("code_verifier"), verifier)
	}
	if !strings.HasPrefix(basic, "Basic ") {
		t.Errorf("客户端认证应为 client_secret_basic，实际 Authorization = %q", basic)
	}

	idToken, err := client.VerifyIDToken(ctx, token.IDToken, "nonce-1")
	if err != nil {
		t.Fatalf("校验 id_token 失败: %v", err)
	}
	if idToken.Subject != "42" {
		t.Errorf("sub = %q", idToken.Subject)
	}
	if idToken.Email != "lisi@example.com" || !idToken.EmailVerified {
		t.Errorf("email claim = %+v", idToken.Claims)
	}
	if idToken.Name != "李四" || idToken.PreferredUsername != "lisi" {
		t.Errorf("profile claim = %+v", idToken.Claims)
	}
	if idToken.Issuer != f.issuer {
		t.Errorf("iss = %q", idToken.Issuer)
	}
	if idToken.PhoneVerified {
		t.Error("phone_number_verified 应为 false")
	}
	if idToken.Raw["sub"] != "42" {
		t.Errorf("Raw 未解码完整声明: %+v", idToken.Raw)
	}
}

func TestVerifyIDTokenRejectsWrongNonce(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	ctx := context.Background()

	token, err := client.Exchange(ctx, "good-code", "any-verifier")
	if err != nil {
		t.Fatalf("换取 token 失败: %v", err)
	}

	if _, err := client.VerifyIDToken(ctx, token.IDToken, "wrong-nonce"); !errors.Is(err, oidcclient.ErrNonceMismatch) {
		t.Fatalf("err = %v, want ErrNonceMismatch", err)
	}
}

func TestVerifyIDTokenRejectsTamperedToken(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	ctx := context.Background()

	token, err := client.Exchange(ctx, "good-code", "any-verifier")
	if err != nil {
		t.Fatalf("换取 token 失败: %v", err)
	}

	parts := strings.Split(token.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token 格式异常: %q", token.IDToken)
	}
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("forged"))
	if _, err := client.VerifyIDToken(ctx, tampered, ""); err == nil {
		t.Fatal("被篡改的 id_token 不应通过校验")
	}
}

func TestUserInfo(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	info, err := client.UserInfo(context.Background(), "access-1")
	if err != nil {
		t.Fatalf("读取 userinfo 失败: %v", err)
	}
	if info.Subject != "42" || info.Name != "李四" || info.Email != "lisi@example.com" {
		t.Fatalf("userinfo = %+v", info)
	}
	if info.Raw["email_verified"] != true {
		t.Errorf("Raw = %+v", info.Raw)
	}
}

func TestUserInfoRejectsBadToken(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	if _, err := client.UserInfo(context.Background(), "expired"); err == nil {
		t.Fatal("无效 access token 应报错")
	}
}

func TestRefreshRotatesTokens(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	refreshed, err := client.Refresh(context.Background(), "refresh-1")
	if err != nil {
		t.Fatalf("刷新 token 失败: %v", err)
	}
	if refreshed.AccessToken != "access-2" {
		t.Errorf("access_token = %q", refreshed.AccessToken)
	}
	if refreshed.RefreshToken != "refresh-2" {
		t.Errorf("refresh_token = %q，轮转后的新值必须返回给调用方", refreshed.RefreshToken)
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  oidcclient.Config
		want error
	}{
		{"空 issuer", oidcclient.Config{ClientID: "c", RedirectURL: "/cb"}, oidcclient.ErrMissingIssuer},
		{"空 client id", oidcclient.Config{Issuer: "https://a.example.com", RedirectURL: "/cb"}, oidcclient.ErrMissingClientID},
		{"空 redirect", oidcclient.Config{Issuer: "https://a.example.com", ClientID: "c"}, oidcclient.ErrMissingRedirectURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := oidcclient.New(context.Background(), tc.cfg); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestEmptyInputsRejected(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	client := newClient(t, f)
	ctx := context.Background()

	if _, err := client.Exchange(ctx, "", ""); !errors.Is(err, oidcclient.ErrMissingCode) {
		t.Errorf("Exchange 空 code: err = %v", err)
	}
	if _, err := client.Refresh(ctx, ""); !errors.Is(err, oidcclient.ErrMissingRefreshToken) {
		t.Errorf("Refresh 空 token: err = %v", err)
	}
	if _, err := client.UserInfo(ctx, ""); !errors.Is(err, oidcclient.ErrMissingAccessToken) {
		t.Errorf("UserInfo 空 token: err = %v", err)
	}
	if _, err := client.VerifyIDToken(ctx, "", ""); !errors.Is(err, oidcclient.ErrMissingIDToken) {
		t.Errorf("VerifyIDToken 空 token: err = %v", err)
	}
}

func TestIssuerMismatchFailsDiscovery(t *testing.T) {
	f := newFakeProvider(t)
	defer f.Close()

	// 用一个与实际 discovery 声明不同的 issuer 触发校验失败。
	_, err := oidcclient.New(context.Background(), oidcclient.Config{
		Issuer:      f.issuer + "/wrong",
		ClientID:    "console",
		RedirectURL: "https://console.example.com/auth/callback",
	})
	if err == nil {
		t.Fatal("issuer 不匹配时不应构建成功")
	}
	if !strings.Contains(err.Error(), fmt.Sprint(404)) && !strings.Contains(err.Error(), "discovery") {
		t.Logf("实际错误: %v", err)
	}
}
