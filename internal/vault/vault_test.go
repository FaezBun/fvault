package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"fvault/internal/crypto"
)

func fastParams() crypto.Params {
	return crypto.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
}

func newTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.json")
	v, err := Create(path, "master-password", "alice", fastParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return v, path
}

func TestCreateAndOpen(t *testing.T) {
	v, path := newTestVault(t)
	if v.Payload.Meta.Username != "alice" {
		t.Fatalf("username = %q", v.Payload.Meta.Username)
	}
	if _, ok := v.Payload.Folders[DefaultFolder]; !ok {
		t.Fatal("default folder missing")
	}

	if _, err := Open(path, "wrong-password"); err == nil {
		t.Fatal("expected an error opening with the wrong password")
	}

	reopened, err := Open(path, "master-password")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if reopened.Payload.Meta.Username != "alice" {
		t.Fatalf("username = %q", reopened.Payload.Meta.Username)
	}
	if len(reopened.Key) != crypto.KeyLen {
		t.Fatalf("key length = %d", len(reopened.Key))
	}
}

func TestOpenMissingFile(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing.json"), "x")
	if err == nil {
		t.Fatal("expected an error for a missing vault")
	}
}

func TestEntryCRUD(t *testing.T) {
	v, _ := newTestVault(t)
	p := v.Payload

	if err := p.AddEntry("server-1", "github", Entry{Username: "octocat", Password: "s3cret", URL: "https://github.com"}); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	if p.FolderCount("server-1") != 1 {
		t.Fatalf("folder count = %d", p.FolderCount("server-1"))
	}
	if err := p.AddEntry("server-1", "github", Entry{Password: "x"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate AddEntry error = %v, want ErrExists", err)
	}

	entry, ok := p.GetEntry("server-1", "github")
	if !ok || entry.Password != "s3cret" {
		t.Fatalf("GetEntry = %+v, %v", entry, ok)
	}
	created := entry.CreatedAt
	if created == "" || entry.UpdatedAt == "" {
		t.Fatal("timestamps were not set")
	}

	if err := p.UpdateEntry("server-1", "github", Entry{Username: "octocat", Password: "new"}); err != nil {
		t.Fatalf("UpdateEntry: %v", err)
	}
	entry, _ = p.GetEntry("server-1", "github")
	if entry.Password != "new" {
		t.Fatalf("password = %q", entry.Password)
	}
	if entry.CreatedAt != created {
		t.Fatalf("CreatedAt changed: %q -> %q", created, entry.CreatedAt)
	}
	if err := p.UpdateEntry("server-1", "missing", Entry{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateEntry missing error = %v", err)
	}

	if err := p.AddEntry("personal", "mail", Entry{Username: "me@example.com", Password: "pw"}); err != nil {
		t.Fatalf("AddEntry personal: %v", err)
	}
	if got := len(p.List()); got != 2 {
		t.Fatalf("List length = %d", got)
	}
	if got := p.Search("git", ""); len(got) != 1 || got[0].Name != "github" {
		t.Fatalf("Search octo = %+v", got)
	}
	if got := p.Search("", "personal"); len(got) != 1 || got[0].Name != "mail" {
		t.Fatalf("Search personal = %+v", got)
	}
	if got := p.Search("nothing", ""); len(got) != 0 {
		t.Fatalf("Search nothing = %+v", got)
	}
	if p.TotalEntries() != 2 {
		t.Fatalf("TotalEntries = %d", p.TotalEntries())
	}

	if err := p.RemoveEntry("server-1", "github"); err != nil {
		t.Fatalf("RemoveEntry: %v", err)
	}
	if err := p.RemoveEntry("server-1", "github"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RemoveEntry missing error = %v", err)
	}
}

func TestFolders(t *testing.T) {
	v, _ := newTestVault(t)
	p := v.Payload

	if err := p.EnsureFolder("server-1"); err != nil {
		t.Fatalf("EnsureFolder: %v", err)
	}
	if err := p.EnsureFolder("server-1"); err != nil {
		t.Fatalf("EnsureFolder twice: %v", err)
	}
	names := p.FolderNames()
	if len(names) != 2 || names[0] != DefaultFolder || names[1] != "server-1" {
		t.Fatalf("FolderNames = %v", names)
	}

	if err := p.RemoveFolder(DefaultFolder, true); !errors.Is(err, ErrDefaultFolder) {
		t.Fatalf("RemoveFolder default error = %v", err)
	}
	if err := p.RemoveFolder("server-1", false); err != nil {
		t.Fatalf("RemoveFolder empty: %v", err)
	}

	if err := p.AddEntry("work", "vpn", Entry{Password: "pw"}); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	if err := p.RemoveFolder("work", false); !errors.Is(err, ErrFolderNotEmpty) {
		t.Fatalf("RemoveFolder nonempty error = %v", err)
	}
	if err := p.RemoveFolder("work", true); err != nil {
		t.Fatalf("RemoveFolder force: %v", err)
	}
	if p.FolderCount("work") != 0 {
		t.Fatal("folder still present after removal")
	}
}

func TestSaveAndReopen(t *testing.T) {
	v, path := newTestVault(t)
	if err := v.Payload.AddEntry("server-2", "db", Entry{Username: "root", Password: "hunter2", Notes: "primary"}); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reopened, err := Open(path, "master-password")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entry, ok := reopened.Payload.GetEntry("server-2", "db")
	if !ok || entry.Password != "hunter2" || entry.Notes != "primary" {
		t.Fatalf("entry = %+v, %v", entry, ok)
	}
}

func TestRekey(t *testing.T) {
	v, path := newTestVault(t)
	if err := v.Rekey("new-master-password", fastParams()); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if _, err := Open(path, "master-password"); err == nil {
		t.Fatal("old password still works after rekey")
	}
	if _, err := Open(path, "new-master-password"); err != nil {
		t.Fatalf("Open with new password: %v", err)
	}
}

func TestValidateNameAndParsePath(t *testing.T) {
	valid := []string{"github", "server-1", "a", "A.b_c-d", "x" + string(make([]byte, 0))}
	for _, name := range valid {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v", name, err)
		}
	}
	invalid := []string{"", "-leading", ".dot", "has space", "slash/name", "é", string(make([]byte, 65))}
	for _, name := range invalid {
		if err := ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) accepted an invalid name", name)
		}
	}

	folder, name, err := ParsePath("github")
	if err != nil || folder != DefaultFolder || name != "github" {
		t.Fatalf("ParsePath single = %q, %q, %v", folder, name, err)
	}
	folder, name, err = ParsePath("server-1/github")
	if err != nil || folder != "server-1" || name != "github" {
		t.Fatalf("ParsePath folder = %q, %q, %v", folder, name, err)
	}
	if _, _, err := ParsePath("a/b/c"); err == nil {
		t.Fatal("ParsePath accepted too many parts")
	}
	if _, _, err := ParsePath("bad folder/name"); err == nil {
		t.Fatal("ParsePath accepted an invalid folder")
	}
}

func TestInspect(t *testing.T) {
	_, path := newTestVault(t)
	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.Version != Version || info.KDFName != KDFName || info.AEADName != AEADName {
		t.Fatalf("info = %+v", info)
	}
	if len(info.Salt) != crypto.SaltLen {
		t.Fatalf("salt length = %d", len(info.Salt))
	}
}

func TestFilePermissions(t *testing.T) {
	_, path := newTestVault(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("vault permissions = %o, want no group/other access", info.Mode().Perm())
	}
}
