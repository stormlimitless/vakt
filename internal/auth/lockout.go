package auth

import (
	"time"

	"github.com/stormlimitless/vakt/internal/store"
)

type Lockout struct {
	Store       *store.Store
	MaxAttempts int
	Duration    time.Duration
	Now         func() time.Time
}

func (l *Lockout) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Lockout) Locked(siteID int64, ip string) (bool, time.Time, error) {
	a, err := l.Store.GetAttempt(siteID, ip)
	if err != nil {
		return false, time.Time{}, err
	}
	if a.LockedUntil.After(l.now()) {
		return true, a.LockedUntil, nil
	}
	return false, time.Time{}, nil
}

func (l *Lockout) Fail(siteID int64, ip string) (bool, error) {
	a, err := l.Store.GetAttempt(siteID, ip)
	if err != nil {
		return false, err
	}
	now := l.now()
	// A lock that has expired starts a fresh count; rows that never locked keep counting up.
	if a.LockedUntil.Unix() > 0 && !a.LockedUntil.After(now) {
		a.Count = 0
	}
	a.Count++
	locked := a.Count >= l.MaxAttempts
	if locked {
		a.LockedUntil = now.Add(l.Duration)
	}
	return locked, l.Store.PutAttempt(a)
}

func (l *Lockout) Reset(siteID int64, ip string) error {
	return l.Store.DeleteAttempt(siteID, ip)
}
