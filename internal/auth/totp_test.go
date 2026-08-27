package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/stormlimitless/vakt/internal/auth"
)

func TestTOTPVerifyAndReplay(t *testing.T) {
	secret, url, err := auth.NewTOTPSecret("Vakt", "henri")
	if err != nil || !strings.HasPrefix(url, "otpauth://totp/Vakt:henri") {
		t.Fatalf("url=%q err=%v", url, err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, _ := totp.GenerateCode(secret, now)
	ok, counter := auth.VerifyTOTP(secret, code, now, 0)
	if !ok || counter != now.Unix()/30 {
		t.Fatalf("ok=%v counter=%d", ok, counter)
	}
	if ok, _ := auth.VerifyTOTP(secret, code, now, counter); ok {
		t.Fatal("replay accepted")
	}
	if ok, _ := auth.VerifyTOTP(secret, "000000", now, 0); ok {
		t.Fatal("wrong code accepted")
	}
	prev, _ := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if ok, _ := auth.VerifyTOTP(secret, prev, now, 0); !ok {
		t.Fatal("previous step should be within window")
	}
}

func TestCipherAndEnrolled(t *testing.T) {
	dir := t.TempDir()
	c, err := auth.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := c.Encrypt([]byte("JBSWY3DPEHPK3PXP"))
	c2, _ := auth.LoadOrCreateKey(dir)
	plain, err := c2.Decrypt(blob)
	if err != nil || string(plain) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("plain=%q err=%v", plain, err)
	}
	if _, err := c2.Decrypt(blob[:len(blob)-1]); err == nil {
		t.Fatal("tampered blob accepted")
	}
	if s, ok := auth.TOTPEnrolled(c2, blob); !ok || s != "JBSWY3DPEHPK3PXP" {
		t.Fatal("enrolled secret not recognised")
	}
	pending, _ := c.Encrypt(auth.PendingSecret("JBSWY3DPEHPK3PXP"))
	if _, ok := auth.TOTPEnrolled(c2, pending); ok {
		t.Fatal("pending secret counted as enrolled")
	}
	if s, ok := auth.TOTPPending(c2, pending); !ok || s != "JBSWY3DPEHPK3PXP" {
		t.Fatal("pending secret not recognised")
	}
	if _, ok := auth.TOTPEnrolled(c2, nil); ok {
		t.Fatal("nil counted as enrolled")
	}
}
