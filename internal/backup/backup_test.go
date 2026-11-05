package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"fvault/internal/config"
	"fvault/internal/crypto"
	"fvault/internal/vault"
)

func testParams() crypto.Params {
	return crypto.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
}

func testSetup(t *testing.T, mode string) (config.Paths, config.Settings, *vault.Vault) {
	t.Helper()
	home := t.TempDir()
	p := config.NewPaths(home)
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	v, err := vault.Create(p.Vault, "master-password", "alice", testParams())
	if err != nil {
		t.Fatalf("vault.Create: %v", err)
	}
	s := config.DefaultSettings(p)
	s.Backup.Enabled = true
	s.Backup.Mode = mode
	s.Backup.LocalDir = p.Backups
	s.Backup.KeepLast = 3
	s.Backup.MaxTotalMB = 0
	return p, s, v
}

func countBackups(t *testing.T, dir string) int {
	t.Helper()
	files, err := listBackupFiles(dir)
	if err != nil {
		t.Fatalf("listBackupFiles: %v", err)
	}
	return len(files)
}

func TestDisabledBackupDoesNothing(t *testing.T) {
	p, s, v := testSetup(t, config.BackupModeNone)
	s.Backup.Enabled = false
	m := New(p, s)
	res, err := m.Create(v.Path, "test")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if res.Path != "" {
		t.Fatalf("path = %q, want empty", res.Path)
	}
	if countBackups(t, p.Backups) != 0 {
		t.Fatal("backup created while disabled")
	}
}

func TestLocalBackupDedupAndRestore(t *testing.T) {
	p, s, v := testSetup(t, config.BackupModeLocal)
	m := New(p, s)

	first, err := m.Create(v.Path, "test")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if first.Path == "" {
		t.Fatal("no snapshot path")
	}
	if countBackups(t, p.Backups) != 1 {
		t.Fatalf("snapshot count = %d", countBackups(t, p.Backups))
	}

	time.Sleep(20 * time.Millisecond)

	second, err := m.Create(v.Path, "test")
	if err != nil {
		t.Fatalf("Create again: %v", err)
	}
	if second.Path != first.Path {
		t.Fatalf("duplicate snapshot created: %q -> %q", first.Path, second.Path)
	}
	if countBackups(t, p.Backups) != 1 {
		t.Fatalf("duplicate snapshot was written; count = %d", countBackups(t, p.Backups))
	}

	if err := v.Payload.AddEntry("server-1", "github", vault.Entry{Password: "s3cret"}); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	third, err := m.Create(v.Path, "after-change")
	if err != nil {
		t.Fatalf("Create after change: %v", err)
	}
	if third.Path == first.Path {
		t.Fatal("new content did not create a new snapshot")
	}
	if countBackups(t, p.Backups) != 2 {
		t.Fatalf("snapshot count = %d", countBackups(t, p.Backups))
	}

	st := m.Status()
	if !st.Enabled || st.LocalCount != 2 || st.Latest == "" {
		t.Fatalf("status = %+v", st)
	}
	records, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}

	res, err := m.Verify(third.Path, "master-password")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 1 {
		t.Fatalf("verify result = %+v", res)
	}
	bad, err := m.Verify(third.Path, "wrong")
	if err != nil {
		t.Fatalf("Verify wrong: %v", err)
	}
	if bad.OK {
		t.Fatal("wrong password verified successfully")
	}
	all, err := m.VerifyAll("master-password")
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("VerifyAll returned %d results", len(all))
	}

	latest, err := m.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	restoredPath := filepath.Join(t.TempDir(), "restored.json")
	if err := m.Restore(latest, restoredPath, "master-password"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restored, err := vault.Open(restoredPath, "master-password")
	if err != nil {
		t.Fatalf("Open restored: %v", err)
	}
	if _, ok := restored.Payload.GetEntry("server-1", "github"); !ok {
		t.Fatal("restored vault is missing the entry")
	}

	exportDir := t.TempDir()
	exported, err := m.Export(filepath.Join(exportDir, "exported.json"), v.Path, "master-password")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, err := vault.Open(exported, "master-password"); err != nil {
		t.Fatalf("Open exported: %v", err)
	}
}

func TestPruneKeepsConfiguredCount(t *testing.T) {
	p, s, v := testSetup(t, config.BackupModeLocal)
	s.Backup.KeepLast = 3
	m := New(p, s)

	for i := 0; i < 5; i++ {
		name := "entry-" + string(rune('a'+i))
		if err := v.Payload.AddEntry("general", name, vault.Entry{Password: "pw"}); err != nil {
			t.Fatalf("AddEntry: %v", err)
		}
		if err := v.Save(); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if _, err := m.Create(v.Path, "loop"); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	if got := countBackups(t, p.Backups); got != 3 {
		t.Fatalf("snapshot count = %d, want 3", got)
	}
}

func TestRemoteBackupAndMarker(t *testing.T) {
	p, s, v := testSetup(t, config.BackupModeLocalRemote)
	s.Backup.RemoteDir = filepath.Join(t.TempDir(), "remote")
	s.Backup.RemoteMarker = "marker-123"
	m := New(p, s)
	if err := m.EnsureRemote(s.Backup.RemoteMarker); err != nil {
		t.Fatalf("EnsureRemote: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Backup.RemoteDir, MarkerName)); err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	if err := m.EnsureRemote("different-marker"); err == nil {
		t.Fatal("marker mismatch was not rejected")
	}

	res, err := m.Create(v.Path, "remote-test")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if res.Warning != "" {
		t.Fatalf("unexpected warning: %s", res.Warning)
	}
	if countBackups(t, s.Backup.RemoteDir) != 1 {
		t.Fatalf("remote snapshot count = %d", countBackups(t, s.Backup.RemoteDir))
	}

	if err := v.Payload.AddEntry("general", "other", vault.Entry{Password: "pw"}); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := m.Create(v.Path, "remote-test-2"); err != nil {
		t.Fatalf("Create 2: %v", err)
	}
	synced, err := m.Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if synced < 1 {
		t.Fatalf("synced = %d", synced)
	}
	st := m.Status()
	if !st.RemoteOK || st.RemoteCount != 2 {
		t.Fatalf("status = %+v", st)
	}
}

func TestRemoteUnavailableIsWarning(t *testing.T) {
	p, s, v := testSetup(t, config.BackupModeLocalRemote)
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s.Backup.RemoteDir = file
	s.Backup.RemoteMarker = "marker"
	m := New(p, s)

	res, err := m.Create(v.Path, "warning-test")
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	if res.Warning == "" {
		t.Fatal("expected a remote warning")
	}
	if res.Path == "" {
		t.Fatal("local snapshot was not created")
	}
	st := m.Status()
	if st.RemoteOK || st.RemoteError == "" {
		t.Fatalf("status = %+v", st)
	}
}
