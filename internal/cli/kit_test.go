package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fvault/internal/config"
)

func TestRenderEmergencyKit(t *testing.T) {
	p := config.Paths{
		Vault:    "/data/pw/vault.json",
		Settings: "/data/pw/settings.json",
		Backups:  "/data/pw/backups",
	}
	out := renderEmergencyKit(p, "alice")
	wants := []string{
		"/data/pw/vault.json",
		"/data/pw/settings.json",
		"/data/pw/backups",
		"alice",
		"never stored",
		"There is no reset",
		"fvault backup restore",
		"Moving to a new computer",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("kit output missing %q\n%s", want, out)
		}
	}
}

func TestRenderEmergencyKitNoUsername(t *testing.T) {
	p := config.Paths{Vault: "/tmp/vault.json"}
	out := renderEmergencyKit(p, "")
	if strings.Contains(out, "Web username") {
		t.Errorf("username line should be omitted when empty:\n%s", out)
	}
}

func TestSaveEmergencyKit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := config.Paths{Vault: "/tmp/vault.json", Settings: "/tmp/settings.json"}
	dest, err := saveEmergencyKit(p, "alice")
	if err != nil {
		t.Fatalf("saveEmergencyKit: %v", err)
	}
	if dest != filepath.Join(home, "fvault-emergency-kit.txt") {
		t.Fatalf("dest = %q", dest)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read kit: %v", err)
	}
	if !strings.Contains(string(data), "alice") {
		t.Fatalf("saved kit missing username:\n%s", data)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("kit file mode = %o, want 600", perm)
	}
}
