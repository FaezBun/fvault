package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"fvault/internal/crypto"
)

const sessionCookie = "fvault_session"

type session struct {
	ID            string
	CSRF          string
	Key           []byte
	Salt          []byte
	Params        crypto.Params
	Username      string
	Authenticated bool
	Expires       time.Time
}

type sessionStore struct {
	mu  sync.Mutex
	m   map[string]*session
	ttl time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &sessionStore{m: map[string]*session{}, ttl: ttl}
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *sessionStore) Create(authenticated bool) (*session, error) {
	id, err := newToken()
	if err != nil {
		return nil, err
	}
	csrf, err := newToken()
	if err != nil {
		return nil, err
	}
	sess := &session{
		ID:            id,
		CSRF:          csrf,
		Authenticated: authenticated,
		Expires:       time.Now().Add(s.ttl),
	}
	s.mu.Lock()
	s.m[id] = sess
	s.mu.Unlock()
	return sess, nil
}

func (s *sessionStore) Get(id string) *session {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil
	}
	if time.Now().After(sess.Expires) {
		delete(s.m, id)
		return nil
	}
	sess.Expires = time.Now().Add(s.ttl)
	return sess
}

func (s *sessionStore) Upgrade(sess *session, key, salt []byte, params crypto.Params, username string) {
	csrf, err := newToken()
	if err == nil {
		sess.CSRF = csrf
	}
	sess.Key = key
	sess.Salt = salt
	sess.Params = params
	sess.Username = username
	sess.Authenticated = true
	sess.Expires = time.Now().Add(s.ttl)
}

func (s *sessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

func (s *sessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.m {
		if now.After(sess.Expires) {
			delete(s.m, id)
		}
	}
}
