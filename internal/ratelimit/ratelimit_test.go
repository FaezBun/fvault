package ratelimit

import (
	"testing"
	"time"
)

func TestLockoutAfterMaxFailures(t *testing.T) {
	l := New(3, 40*time.Millisecond)
	key := "192.0.2.1"

	if ok, _ := l.Allowed(key); !ok {
		t.Fatal("new key should be allowed")
	}
	if locked, _ := l.Failure(key); locked {
		t.Fatal("locked after one failure")
	}
	if locked, _ := l.Failure(key); locked {
		t.Fatal("locked after two failures")
	}
	locked, retry := l.Failure(key)
	if !locked {
		t.Fatal("not locked after three failures")
	}
	if retry <= 0 {
		t.Fatalf("retry duration = %v", retry)
	}
	if ok, _ := l.Allowed(key); ok {
		t.Fatal("key should be locked")
	}

	time.Sleep(60 * time.Millisecond)
	if ok, _ := l.Allowed(key); !ok {
		t.Fatal("key should be allowed after the lockout expires")
	}
	// The failure counter must have been reset after expiry.
	if locked, _ := l.Failure(key); locked {
		t.Fatal("lockout did not reset the failure counter")
	}
}

func TestSuccessResets(t *testing.T) {
	l := New(3, time.Minute)
	key := "192.0.2.2"
	l.Failure(key)
	l.Failure(key)
	l.Success(key)
	if locked, _ := l.Failure(key); locked {
		t.Fatal("success did not reset the failure counter")
	}
	if locked, _ := l.Failure(key); locked {
		t.Fatal("locked too early after reset")
	}
	if locked, _ := l.Failure(key); !locked {
		t.Fatal("expected lockout after three fresh failures")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, time.Minute)
	if locked, _ := l.Failure("a"); !locked {
		t.Fatal("first key not locked")
	}
	if ok, _ := l.Allowed("b"); !ok {
		t.Fatal("second key should not be locked")
	}
}

func TestCleanup(t *testing.T) {
	l := New(3, time.Minute)
	l.now = func() time.Time { return time.Unix(1000, 0) }
	l.Failure("old")
	l.now = func() time.Time { return time.Unix(1000+25*3600, 0) }
	l.Failure("new")
	l.Cleanup()
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.entries["old"]; ok {
		t.Fatal("old entry was not removed")
	}
	if _, ok := l.entries["new"]; !ok {
		t.Fatal("new entry was removed")
	}
}
