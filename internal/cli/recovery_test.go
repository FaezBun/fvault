package cli

import (
	"errors"
	"testing"

	"fvault/internal/config"
	"fvault/internal/crypto"
	"fvault/internal/recovery"
	"fvault/internal/vault"
)

func recoveryFixture(t *testing.T) (config.Paths, *vault.Vault) {
	t.Helper()
	p := config.NewPaths(t.TempDir())
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	v, err := vault.Create(p.Vault, "old-master-pass", "alice", crypto.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return p, v
}

func TestRecoverySetupAndResetRoundtrip(t *testing.T) {
	p, v := recoveryFixture(t)
	questions := []string{recovery.Questions[0], recovery.Questions[1], recovery.Questions[2]}
	answers := []string{"Smith", "Fluffy", "Kuala Lumpur"}

	if err := applyRecoverySetup(p, questions, answers, v); err != nil {
		t.Fatalf("applyRecoverySetup: %v", err)
	}
	if !recovery.Configured(p.Recovery) {
		t.Fatal("recovery file missing")
	}

	// Reset with the answers and a new password.
	if err := applyRecoveryReset(p, answers, "new-master-pass-1"); err != nil {
		t.Fatalf("applyRecoveryReset: %v", err)
	}

	// Old password is gone, new one works.
	if _, err := vault.Open(p.Vault, "old-master-pass"); err == nil {
		t.Fatal("old password must no longer open the vault")
	}
	opened, err := vault.Open(p.Vault, "new-master-pass-1")
	if err != nil {
		t.Fatalf("new password: %v", err)
	}
	if opened.Payload.Meta.Username != "alice" {
		t.Fatalf("username = %q", opened.Payload.Meta.Username)
	}
	if len(opened.Payload.Audit) == 0 || opened.Payload.Audit[len(opened.Payload.Audit)-1].Action != "vault.rekey" {
		t.Fatalf("audit tail = %+v", opened.Payload.Audit)
	}

	// The questions still work after the reset (blob was re-wrapped).
	key, err := recovery.OpenVaultKey(p.Recovery, answers)
	if err != nil {
		t.Fatalf("recovery after reset: %v", err)
	}
	if string(key) != string(opened.Key) {
		t.Fatalf("recovered key does not match the vault key")
	}
	// Wrong answers still fail.
	if _, err := recovery.OpenVaultKey(p.Recovery, []string{"Nope", "Nope", "Nope"}); !errors.Is(err, recovery.ErrInvalidAnswer) {
		t.Fatalf("wrong answers err = %v", err)
	}
}

func TestRecoveryResetWithoutSetup(t *testing.T) {
	p, _ := recoveryFixture(t)
	if err := applyRecoveryReset(p, []string{"a", "b", "c"}, "whatever123"); !errors.Is(err, recovery.ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}
