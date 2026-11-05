package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Paths holds the runtime file locations for a FVault installation.
type Paths struct {
	Home     string
	Vault    string
	Settings string
	Secret   string
	Backups  string
}

// ResolveHome returns the absolute data directory. Priority:
// explicit override, FVAULT_HOME environment variable, then ./data.
func ResolveHome(override string) (string, error) {
	home := override
	if home == "" {
		home = os.Getenv("FVAULT_HOME")
	}
	if home == "" {
		home = "data"
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func NewPaths(home string) Paths {
	return Paths{
		Home:     home,
		Vault:    filepath.Join(home, "vault.json"),
		Settings: filepath.Join(home, "settings.json"),
		Secret:   filepath.Join(home, "secret.key"),
		Backups:  filepath.Join(home, "backups"),
	}
}

// Ensure creates the data directory and backup directory with restrictive
// permissions.
func (p Paths) Ensure() error {
	if err := os.MkdirAll(p.Home, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(p.Home, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(p.Backups, 0o700); err != nil {
		return err
	}
	return os.Chmod(p.Backups, 0o700)
}

// WriteAtomic writes data to path using a temporary file in the same directory
// followed by rename. It fsyncs the file and directory so a crash cannot leave
// a partially written file behind.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".fvault-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// EnsureSecret loads (or creates) the web session signing secret. The secret
// is not used to encrypt the vault; losing it only invalidates web sessions.
func EnsureSecret(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" {
			key, err := hex.DecodeString(s)
			if err == nil && len(key) == 32 {
				return key, nil
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := WriteAtomic(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
