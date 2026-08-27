package auth

import (
	"time"

	"github.com/stormlimitless/vakt/internal/store"
)

type Sessions struct{ Store *store.Store }

func (s *Sessions) Create(siteID, userID int64, kind, ip string, ttl time.Duration) (string, error) {
	tok, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	err = s.Store.CreateSession(&store.Session{TokenHash: TokenHash(tok), SiteID: siteID, UserID: userID, Kind: kind, IP: ip, ExpiresAt: time.Now().Add(ttl)})
	return tok, err
}

func (s *Sessions) Lookup(token string) (*store.Session, bool) {
	if token == "" {
		return nil, false
	}
	sess, err := s.Store.SessionByTokenHash(TokenHash(token))
	if err != nil {
		return nil, false
	}
	return sess, true
}

func (s *Sessions) Delete(token string) error {
	sess, ok := s.Lookup(token)
	if !ok {
		return nil
	}
	return s.Store.DeleteSession(sess.ID)
}
