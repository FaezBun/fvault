package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fvault/internal/config"
	"fvault/internal/vault"
)

func TestCreateVaultQuickWithBackups(t *testing.T) {
	p := config.NewPaths(t.TempDir())
	v, settings, warning, err := createVaultQuick(p, "alice", "password123", true)
	if err != nil {
		t.Fatalf("createVaultQuick: %v", err)
	}
	if warning != "" {
		t.Fatalf("warning = %q", warning)
	}
	if v.Payload.Meta.Username != "alice" {
		t.Fatalf("username = %q", v.Payload.Meta.Username)
	}
	if !settings.BackupEnabled() || settings.Backup.Mode != config.BackupModeLocal {
		t.Fatalf("settings = %+v", settings)
	}
	if settings.Backup.LocalDir != p.Backups {
		t.Fatalf("local dir = %q", settings.Backup.LocalDir)
	}

	if _, err := os.Stat(p.Vault); err != nil {
		t.Fatalf("vault file: %v", err)
	}
	if _, err := os.Stat(p.Secret); err != nil {
		t.Fatalf("secret file: %v", err)
	}
	entries, err := os.ReadDir(p.Backups)
	if err != nil {
		t.Fatalf("ReadDir backups: %v", err)
	}
	snapshots := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "vault-") && strings.HasSuffix(e.Name(), ".json") {
			snapshots++
		}
	}
	if snapshots != 1 {
		t.Fatalf("snapshots = %d, want 1", snapshots)
	}

	opened, err := vault.Open(p.Vault, "password123")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.Payload.Meta.Username != "alice" {
		t.Fatalf("opened username = %q", opened.Payload.Meta.Username)
	}
}

func TestCreateVaultQuickWithoutBackups(t *testing.T) {
	p := config.NewPaths(t.TempDir())
	_, settings, warning, err := createVaultQuick(p, "bob", "password123", false)
	if err != nil {
		t.Fatalf("createVaultQuick: %v", err)
	}
	if warning != "" {
		t.Fatalf("warning = %q", warning)
	}
	if settings.BackupEnabled() {
		t.Fatalf("backups should be disabled: %+v", settings)
	}
	entries, err := os.ReadDir(p.Backups)
	if err != nil {
		t.Fatalf("ReadDir backups: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("backup folder is not empty: %v", entries)
	}
}

func TestCreateVaultQuickRejectsEmptyUsername(t *testing.T) {
	p := config.NewPaths(t.TempDir())
	if _, _, _, err := createVaultQuick(p, "", "password123", false); err == nil {
		t.Fatal("expected an error for an empty username")
	}
}

func TestCreateVaultQuickLeavesRestrictivePermissions(t *testing.T) {
	p := config.NewPaths(t.TempDir())
	if _, _, _, err := createVaultQuick(p, "alice", "password123", false); err != nil {
		t.Fatalf("createVaultQuick: %v", err)
	}
	info, err := os.Stat(filepath.Join(p.Home, "vault.json"))
	if err != nil {
		t.Fatalf("Stat vault: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("vault permissions = %o", info.Mode().Perm())
	}
}
