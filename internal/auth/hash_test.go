package auth_test

import (
	"testing"

	"github.com/stormlimitless/vakt/internal/auth"
)

func TestHashVerify(t *testing.T) {
	h, err := auth.HashSecret("482913")
	if err != nil || !auth.VerifySecret(h, "482913") || auth.VerifySecret(h, "482914") || auth.VerifySecret("garbage", "x") {
		t.Fatalf("h=%s err=%v", h, err)
	}
	if h2, _ := auth.HashSecret("482913"); h == h2 {
		t.Fatal("salt not random")
	}
}

func TestTokens(t *testing.T) {
	tok, err := auth.RandomToken(32)
	if err != nil || len(tok) < 40 {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	if auth.TokenHash(tok) == auth.TokenHash(tok+"x") || len(auth.TokenHash(tok)) != 64 {
		t.Fatal("bad token hash")
	}
}
