package handler

import (
	"encoding/base64"
	"net/url"
	"testing"
)

// 标准客户端（Java/Node/Python）默认用 client_secret_basic 提交凭据，
// 解析必须能还原 form 编码并容忍 secret 内含冒号，否则一律 401。
func TestParseBasicAuth(t *testing.T) {
	encode := func(raw string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
	}
	// RFC 6749 §2.3.1：凭据先做 application/x-www-form-urlencoded 编码再拼进 Basic，
	// 因此头里的 "+" 代表空格，取出来必须还原。
	formEncoded := encode(url.QueryEscape("client id") + ":" + url.QueryEscape("sec/ret +="))

	cases := []struct {
		name       string
		header     string
		wantID     string
		wantSecret string
		wantOK     bool
	}{
		{name: "标准凭据", header: encode("my-client:my-secret"), wantID: "my-client", wantSecret: "my-secret", wantOK: true},
		{name: "secret 含冒号", header: encode("c:p:a:ss"), wantID: "c", wantSecret: "p:a:ss", wantOK: true},
		{name: "form 编码凭据", header: formEncoded, wantID: "client id", wantSecret: "sec/ret +=", wantOK: true},
		{name: "空头", header: "", wantOK: false},
		{name: "非 Basic 方案", header: "Bearer abc", wantOK: false},
		{name: "非法 base64", header: "Basic ***", wantOK: false},
		{name: "缺少冒号", header: encode("onlyid"), wantOK: false},
		{name: "非法百分号编码", header: encode("a%zz:b"), wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, secret, ok := parseBasicAuth(tc.header)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if id != tc.wantID || secret != tc.wantSecret {
				t.Fatalf("got (%q, %q), want (%q, %q)", id, secret, tc.wantID, tc.wantSecret)
			}
		})
	}
}
