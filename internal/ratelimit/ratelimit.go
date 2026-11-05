package ratelimit

import (
	"sync"
	"time"
)

type state struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

// Limiter tracks failed login attempts per key (normally a client IP).
// A key is locked for the configured duration after max failures.
type Limiter struct {
	mu      sync.Mutex
	max     int
	lockout time.Duration
	entries map[string]*state
	now     func() time.Time
}

func New(max int, lockout time.Duration) *Limiter {
	if max <= 0 {
		max = 10
	}
	if lockout <= 0 {
		lockout = 15 * time.Minute
	}
	return &Limiter{
		max:     max,
		lockout: lockout,
		entries: map[string]*state{},
		now:     time.Now,
	}
}

// Allowed reports whether the key may attempt a login now, and if not, how
// long remains until the lock expires.
func (l *Limiter) Allowed(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	s, ok := l.entries[key]
	if !ok {
		return true, 0
	}
	s.lastSeen = now
	if s.lockedUntil.After(now) {
		return false, s.lockedUntil.Sub(now)
	}
	if !s.lockedUntil.IsZero() {
		// Lock expired: reset the counter so the user gets a fresh set of
		// attempts instead of being locked again on the next failure.
		s.failures = 0
		s.lockedUntil = time.Time{}
	}
	return true, 0
}

// Failure records a failed attempt and returns whether the key is now locked.
func (l *Limiter) Failure(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	s, ok := l.entries[key]
	if !ok {
		s = &state{}
		l.entries[key] = s
	}
	s.failures++
	s.lastSeen = now
	if s.failures >= l.max {
		s.lockedUntil = now.Add(l.lockout)
		return true, l.lockout
	}
	return false, 0
}

func (l *Limiter) Success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Cleanup removes entries that have not been seen for a while. Call it
// periodically from the web server.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for key, s := range l.entries {
		if now.Sub(s.lastSeen) > 24*time.Hour {
			delete(l.entries, key)
		}
	}
}
