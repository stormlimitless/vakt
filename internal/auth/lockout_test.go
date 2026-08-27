package auth_test

import (
	"testing"
	"time"

	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/store"
)

func TestLockoutAfterMaxAttempts(t *testing.T) {
	s, _ := store.Open(t.TempDir())
	defer s.Close()
	now := time.Unix(1_000_000, 0)
	l := &auth.Lockout{Store: s, MaxAttempts: 3, Duration: 15 * time.Minute, Now: func() time.Time { return now }}
	for i := 0; i < 2; i++ {
		if locked, err := l.Fail(1, "9.9.9.9"); err != nil || locked {
			t.Fatalf("i=%d locked=%v err=%v", i, locked, err)
		}
	}
	if locked, _ := l.Fail(1, "9.9.9.9"); !locked {
		t.Fatal("expected lock on 3rd failure")
	}
	isLocked, until, _ := l.Locked(1, "9.9.9.9")
	if !isLocked || !until.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("locked=%v until=%v", isLocked, until)
	}
	if isLocked, _, _ = l.Locked(2, "9.9.9.9"); isLocked {
		t.Fatal("lock leaked across sites")
	}
	now = now.Add(16 * time.Minute)
	if isLocked, _, _ = l.Locked(1, "9.9.9.9"); isLocked {
		t.Fatal("lock did not expire")
	}
	if locked, _ := l.Fail(1, "9.9.9.9"); locked {
		t.Fatal("count should reset after expiry")
	}
	l.Reset(1, "9.9.9.9")
	if a, _ := s.GetAttempt(1, "9.9.9.9"); a.Count != 0 {
		t.Fatal("reset failed")
	}
}
