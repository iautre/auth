package secretbox

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// 固定一把 32 字节密钥（base64），让整个包的测试都跑在加密模式。
	os.Setenv(EnvKey, "iI69Qwwnteg5Xh9H2FVAnFVeh5qGSTpFQVf8myi2PbM=")
	os.Setenv("BASE_URL", "http://localhost:8080")
	os.Exit(m.Run())
}

func TestSealOpenRoundTrip(t *testing.T) {
	sealed, err := Seal("very-secret-value")
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if !IsSealed(sealed) {
		t.Fatalf("Seal() = %q, want enc:v1: prefix", sealed)
	}
	if strings.Contains(sealed, "very-secret-value") {
		t.Fatal("Seal() 泄漏了明文")
	}

	plain, err := Open(sealed)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if plain != "very-secret-value" {
		t.Fatalf("Open() = %q, want %q", plain, "very-secret-value")
	}
}

func TestSealIsRandomised(t *testing.T) {
	first, err := Seal("same-value")
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	second, err := Seal("same-value")
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if first == second {
		t.Fatal("相同明文产生了相同密文，nonce 没有随机化")
	}
}

func TestOpenLegacyPlaintext(t *testing.T) {
	// 存量明文（没有 enc:v1: 前缀）必须原样返回，便于逐条升级。
	plain, err := Open("legacy-plain-secret")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if plain != "legacy-plain-secret" {
		t.Fatalf("Open() = %q, want 原样返回", plain)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	sealed, err := Seal("tamper-me")
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	// 改掉密文最后一个字符，GCM 应当校验失败。
	tampered := sealed[:len(sealed)-2] + "AA"
	if _, err := Open(tampered); err == nil {
		t.Fatal("篡改后的密文应当解密失败")
	}
}

func TestSealEmptyValue(t *testing.T) {
	sealed, err := Seal("")
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if sealed != "" {
		t.Fatalf("Seal(\"\") = %q, want 空串", sealed)
	}
}
