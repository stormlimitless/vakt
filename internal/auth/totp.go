package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// A secret stored with this prefix has been generated but not yet confirmed
// by the user, so login treats it as "not enrolled".
const pendingPrefix = "pending:"

type Cipher struct{ key []byte }

func LoadOrCreateKey(dir string) (*Cipher, error) {
	path := filepath.Join(dir, "secret.key")
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("secret.key must be 32 bytes")
	}
	return &Cipher{key: key}, nil
}

func (c *Cipher) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *Cipher) Encrypt(plain []byte) ([]byte, error) {
	g, err := c.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, nil), nil
}

func (c *Cipher) Decrypt(blob []byte) ([]byte, error) {
	g, err := c.gcm()
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], nil)
}

func NewTOTPSecret(issuer, account string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func VerifyTOTP(secret, code string, now time.Time, lastUsed int64) (bool, int64) {
	for _, delta := range []int64{0, -1, 1} {
		t := now.Add(time.Duration(delta) * 30 * time.Second)
		counter := t.Unix() / 30
		if counter <= lastUsed {
			continue
		}
		ok, err := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && ok {
			return true, counter
		}
	}
	return false, 0
}

func PendingSecret(secret string) []byte { return []byte(pendingPrefix + secret) }

func TOTPEnrolled(c *Cipher, enc []byte) (string, bool) {
	plain, ok := decrypt(c, enc)
	if !ok || strings.HasPrefix(plain, pendingPrefix) {
		return "", false
	}
	return plain, true
}

func TOTPPending(c *Cipher, enc []byte) (string, bool) {
	plain, ok := decrypt(c, enc)
	if !ok || !strings.HasPrefix(plain, pendingPrefix) {
		return "", false
	}
	return strings.TrimPrefix(plain, pendingPrefix), true
}

func decrypt(c *Cipher, enc []byte) (string, bool) {
	if c == nil || len(enc) == 0 {
		return "", false
	}
	plain, err := c.Decrypt(enc)
	if err != nil {
		return "", false
	}
	return string(plain), true
}
