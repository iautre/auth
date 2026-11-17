package service

import (
	"errors"
	"testing"
)

// client 登记的 scopes 是授权边界的唯一依据。校验缺失时，只登记 openid 的
// 客户端可以索取 phone，把手机号带进 id_token。
func TestValidateAuthScopes(t *testing.T) {
	tests := []struct {
		name     string
		allowed  string
		request  string
		wantCode string
	}{
		{name: "全部在登记范围内", allowed: `["openid","profile"]`, request: "openid profile"},
		{name: "请求越权 scope", allowed: `["openid"]`, request: "openid phone", wantCode: OAuthErrInvalidScope},
		{name: "未登记列表视为不限制", allowed: `[]`, request: "openid phone email"},
		{name: "空请求不报错", allowed: `["openid"]`, request: ""},
		{name: "配置损坏", allowed: `not-json`, request: "openid", wantCode: OAuthErrInvalidRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAuthScopes(test.allowed, test.request)
			if test.wantCode == "" {
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
				return
			}
			var oauthErr *OAuthError
			if !errors.As(err, &oauthErr) || oauthErr.Code != test.wantCode {
				t.Fatalf("error = %v, want code %q", err, test.wantCode)
			}
		})
	}
}

// 客户端认证失败必须是 401 invalid_client。若压成 invalid_grant(400)，
// 第三方库会误判成"授权码有问题"，进而反复重走授权流程。
func TestAuthenticateClientErrorsAreInvalidClient(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{name: "缺少 client_id"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var svc OAuth2Service
			_, err := svc.authenticateClient(t.Context(), test.clientID, test.clientSecret)
			var oauthErr *OAuthError
			if !errors.As(err, &oauthErr) {
				t.Fatalf("error = %v, want *OAuthError", err)
			}
			if oauthErr.Code != OAuthErrInvalidClient || oauthErr.Status != 401 {
				t.Fatalf("code/status = %q/%d, want invalid_client/401", oauthErr.Code, oauthErr.Status)
			}
		})
	}
}
