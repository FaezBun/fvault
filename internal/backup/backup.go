package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fvault/internal/config"
	"fvault/internal/vault"
)

const MarkerName = ".fvault-target"

type Manager struct {
	Paths    config.Paths
	Settings config.Settings
}

type Record struct {
	Name    string
	Path    string
	Dir     string
	Size    int64
	ModTime time.Time
	Local   bool
	Remote  bool
}

type CreateResult struct {
	Path    string
	Warning string
}

type Status struct {
	Enabled      bool
	Mode         string
	LocalDir     string
	RemoteDir    string
	LocalCount   int
	LocalBytes   int64
	RemoteCount  int
	RemoteBytes  int64
	Latest       string
	RemoteOK     bool
	RemoteError  string
	KeepLast     int
	MaxTotalMB   int
	RemoteMarker string
}

type VerifyResult struct {
	Name    string
	Path    string
	OK      bool
	Folders int
	Entries int
	Error   string
}

func New(p config.Paths, s config.Settings) *Manager {
	return &Manager{Paths: p, Settings: s}
}

func (m *Manager) LocalDir() string {
	if m.Settings.Backup.LocalDir != "" {
		return m.Settings.Backup.LocalDir
	}
	return m.Paths.Backups
}

func (m *Manager) RemoteDir() string {
	return m.Settings.Backup.RemoteDir
}

func (m *Manager) EnsureRemote(marker string) error {
	dir := m.RemoteDir()
	if dir == "" {
		return errors.New("remote folder is not configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	markerPath := filepath.Join(dir, MarkerName)
	b, err := os.ReadFile(markerPath)
	if err == nil {
		existing := strings.TrimSpace(string(b))
		if marker != "" && existing != marker {
			return fmt.Errorf("remote marker mismatch in %s; refusing to use this folder", dir)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if marker == "" {
		return errors.New("remote backup marker is missing; run 'fvault backup setup'")
	}
	return config.WriteAtomic(markerPath, []byte(marker+"\n"), 0o600)
}

func (m *Manager) checkRemote() error {
	if !m.Settings.HasRemote() {
		return errors.New("remote backup is not enabled")
	}
	if m.Settings.Backup.RemoteMarker == "" {
		return errors.New("remote marker is not configured; run 'fvault backup setup'")
	}
	return m.EnsureRemote(m.Settings.Backup.RemoteMarker)
}

func (m *Manager) Create(vaultPath, reason string) (CreateResult, error) {
	res := CreateResult{}
	if !m.Settings.BackupEnabled() {
		return res, nil
	}
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return res, err
	}
	sum := sha256Hex(data)
	name := backupName(reason)

	var savedLocal string
	if m.Settings.HasLocal() {
		dir := m.LocalDir()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return res, err
		}
		latest := latestBackupFile(dir)
		if latest != "" {
			if old, err := fileSHA(latest); err == nil && old == sum {
				savedLocal = latest
			}
		}
		if savedLocal == "" {
			savedLocal, err = writeUnique(dir, name, data)
			if err != nil {
				return res, err
			}
		}
		if err := m.PruneDir(dir); err != nil {
			res.Warning = appendWarning(res.Warning, err.Error())
		}
	}

	if m.Settings.HasRemote() {
		if err := m.checkRemote(); err != nil {
			res.Warning = appendWarning(res.Warning, "remote backup failed: "+err.Error())
		} else {
			dir := m.RemoteDir()
			remoteName := name
			if savedLocal != "" {
				remoteName = filepath.Base(savedLocal)
			}
			if err := m.copyIfChanged(savedLocal, dir, remoteName, data, sum); err != nil {
				res.Warning = appendWarning(res.Warning, "remote backup failed: "+err.Error())
			}
			if err := m.PruneDir(dir); err != nil {
				res.Warning = appendWarning(res.Warning, err.Error())
			}
		}
	}

	switch {
	case savedLocal != "":
		res.Path = savedLocal
	case m.Settings.HasRemote():
		res.Path = filepath.Join(m.RemoteDir(), name)
	}
	return res, nil
}

func (m *Manager) copyIfChanged(sourceDir, destDir, name string, data []byte, sum string) error {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return err
	}
	dest := filepath.Join(destDir, name)
	if old, err := fileSHA(dest); err == nil && old == sum {
		return nil
	}
	return config.WriteAtomic(dest, data, 0o600)
}

func (m *Manager) PruneDir(dir string) error {
	keep := m.Settings.Backup.KeepLast
	if keep <= 0 {
		keep = 10
	}
	maxBytes := int64(m.Settings.Backup.MaxTotalMB) * 1024 * 1024
	files, err := listBackupFiles(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(files) == 0 {
		return nil
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.Before(files[j].ModTime)
	})
	var total int64
	for _, f := range files {
		total += f.Size
	}
	for len(files) > 1 {
		overCount := len(files) > keep
		overSize := maxBytes > 0 && total > maxBytes
		if !overCount && !overSize {
			break
		}
		oldest := files[0]
		if err := os.Remove(oldest.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		total -= oldest.Size
		files = files[1:]
	}
	return nil
}

func (m *Manager) Sync() (int, error) {
	if !m.Settings.HasRemote() {
		return 0, errors.New("remote backup is not enabled")
	}
	if err := m.checkRemote(); err != nil {
		return 0, err
	}
	files, err := listBackupFiles(m.LocalDir())
	if err != nil {
		return 0, err
	}
	copied := 0
	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			return copied, err
		}
		sum := sha256Hex(data)
		if err := m.copyIfChanged(m.LocalDir(), m.RemoteDir(), f.Name, data, sum); err != nil {
			return copied, err
		}
		copied++
	}
	if err := m.PruneDir(m.RemoteDir()); err != nil {
		return copied, err
	}
	return copied, nil
}

func (m *Manager) List() ([]Record, error) {
	byName := map[string]*Record{}
	add := func(dir string, local, remote bool) error {
		files, err := listBackupFiles(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		for _, f := range files {
			rec, ok := byName[f.Name]
			if !ok {
				rec = &Record{Name: f.Name, Path: f.Path, Dir: dir, Size: f.Size, ModTime: f.ModTime}
				byName[f.Name] = rec
			}
			if local {
				rec.Local = true
			}
			if remote {
				rec.Remote = true
			}
		}
		return nil
	}
	if m.Settings.HasLocal() {
		if err := add(m.LocalDir(), true, false); err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(m.LocalDir()); err == nil {
		_ = add(m.LocalDir(), true, false)
	}
	if m.Settings.HasRemote() {
		if err := add(m.RemoteDir(), false, true); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	out := make([]Record, 0, len(byName))
	for _, r := range byName {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ModTime.After(out[j].ModTime)
	})
	return out, nil
}

func (m *Manager) Status() Status {
	st := Status{
		Enabled:      m.Settings.BackupEnabled(),
		Mode:         m.Settings.Backup.Mode,
		LocalDir:     m.LocalDir(),
		RemoteDir:    m.RemoteDir(),
		KeepLast:     m.Settings.Backup.KeepLast,
		MaxTotalMB:   m.Settings.Backup.MaxTotalMB,
		RemoteMarker: m.Settings.Backup.RemoteMarker,
	}
	if files, err := listBackupFiles(m.LocalDir()); err == nil {
		st.LocalCount = len(files)
		for _, f := range files {
			st.LocalBytes += f.Size
		}
		if len(files) > 0 {
			sort.Slice(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })
			st.Latest = files[0].Name
		}
	}
	if m.Settings.HasRemote() {
		if err := m.checkRemote(); err != nil {
			st.RemoteError = err.Error()
		} else {
			st.RemoteOK = true
			if files, err := listBackupFiles(m.RemoteDir()); err == nil {
				st.RemoteCount = len(files)
				for _, f := range files {
					st.RemoteBytes += f.Size
				}
			}
		}
	}
	return st
}

func (m *Manager) Latest() (string, error) {
	if m.Settings.HasLocal() {
		if latest := latestBackupFile(m.LocalDir()); latest != "" {
			return latest, nil
		}
	}
	if m.Settings.HasRemote() {
		if err := m.checkRemote(); err == nil {
			if latest := latestBackupFile(m.RemoteDir()); latest != "" {
				return latest, nil
			}
		}
	}
	return "", errors.New("no backups found")
}

func (m *Manager) Verify(path, password string) (VerifyResult, error) {
	res := VerifyResult{Name: filepath.Base(path), Path: path}
	v, err := vault.Open(path, password)
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	res.OK = true
	res.Folders = len(v.Payload.Folders)
	res.Entries = v.Payload.TotalEntries()
	return res, nil
}

func (m *Manager) VerifyAll(password string) ([]VerifyResult, error) {
	files, err := listBackupFiles(m.LocalDir())
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no local backups found")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })
	out := make([]VerifyResult, 0, len(files))
	for _, f := range files {
		res, _ := m.Verify(f.Path, password)
		out = append(out, res)
	}
	return out, nil
}

func (m *Manager) Restore(backupPath, vaultPath, password string) error {
	if _, err := vault.Open(backupPath, password); err != nil {
		return fmt.Errorf("backup cannot be decrypted: %w", err)
	}
	if _, err := os.Stat(vaultPath); err == nil {
		if err := os.MkdirAll(m.Paths.Backups, 0o700); err != nil {
			return err
		}
		current, err := os.ReadFile(vaultPath)
		if err != nil {
			return err
		}
		name := fmt.Sprintf("vault-%s-pre-restore.json", time.Now().UTC().Format("20060102-150405"))
		saved, err := writeUnique(m.Paths.Backups, name, current)
		if err != nil {
			return err
		}
		_ = saved
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	if err := config.WriteAtomic(vaultPath, data, 0o600); err != nil {
		return err
	}
	if _, err := vault.Open(vaultPath, password); err != nil {
		return fmt.Errorf("restored vault failed verification: %w", err)
	}
	return nil
}

func (m *Manager) Export(dest, vaultPath, password string) (string, error) {
	if _, err := vault.Open(vaultPath, password); err != nil {
		return "", err
	}
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(dest); err == nil && info.IsDir() {
		dest = filepath.Join(dest, fmt.Sprintf("vault-export-%s.json", time.Now().UTC().Format("20060102-150405")))
	}
	if err := config.WriteAtomic(dest, data, 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

type fileRecord struct {
	Name    string
	Path    string
	Size    int64
	ModTime time.Time
}

func listBackupFiles(dir string) ([]fileRecord, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []fileRecord
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "vault-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if strings.Contains(name, "corrupt") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, fileRecord{
			Name:    name,
			Path:    filepath.Join(dir, name),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	return out, nil
}

func latestBackupFile(dir string) string {
	files, err := listBackupFiles(dir)
	if err != nil || len(files) == 0 {
		return ""
	}
	sort.Slice(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })
	return files[0].Path
}

func writeUnique(dir, name string, data []byte) (string, error) {
	base := strings.TrimSuffix(name, ".json")
	path := filepath.Join(dir, name)
	for i := 1; ; i++ {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			break
		}
		path = filepath.Join(dir, fmt.Sprintf("%s-%d.json", base, i))
	}
	if err := config.WriteAtomic(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func backupName(reason string) string {
	reason = sanitize(reason)
	if reason == "" {
		reason = "auto"
	}
	return fmt.Sprintf("vault-%s-%s.json", time.Now().UTC().Format("20060102-150405"), reason)
}

func sanitize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func fileSHA(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(b), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func appendWarning(existing, msg string) string {
	if existing == "" {
		return msg
	}
	return existing + "; " + msg
}
