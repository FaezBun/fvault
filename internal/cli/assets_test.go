package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAssetDirFlagWins(t *testing.T) {
	t.Setenv("FVAULT_TEST_ASSETS", "/from/env")
	got := resolveAssetDir("/from/flag", "FVAULT_TEST_ASSETS", "templates")
	if got != "/from/flag" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveAssetDirEnvironment(t *testing.T) {
	t.Setenv("FVAULT_TEST_ASSETS", "/from/env")
	got := resolveAssetDir("", "FVAULT_TEST_ASSETS", "templates")
	if got != "/from/env" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveAssetDirCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Chdir(dir)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	got := resolveAssetDir("", "FVAULT_TEST_ASSETS_UNSET", "templates")
	if got != "templates" {
		t.Fatalf("got %q, want current-directory templates", got)
	}
}

func TestResolveAssetDirDataHome(t *testing.T) {
	dir := t.TempDir()
	dataHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataHome, "fvault", "templates"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Chdir(dir)
	t.Setenv("XDG_DATA_HOME", dataHome)
	want := filepath.Join(dataHome, "fvault", "templates")
	got := resolveAssetDir("", "FVAULT_TEST_ASSETS_UNSET", "templates")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveAssetDirFallback(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	got := resolveAssetDir("", "FVAULT_TEST_ASSETS_UNSET", "fvault-missing-assets-xyz")
	if got != "fvault-missing-assets-xyz" {
		t.Fatalf("got %q", got)
	}
}
