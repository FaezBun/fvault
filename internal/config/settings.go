package config

import (
	"encoding/json"
	"errors"
	"os"
)

const (
	BackupModeNone        = "none"
	BackupModeLocal       = "local"
	BackupModeLocalRemote = "local+remote"
	BackupModeRemote      = "remote"
)

type BackupSettings struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	LocalDir      string `json:"local_dir"`
	RemoteDir     string `json:"remote_dir"`
	RemoteMarker  string `json:"remote_marker,omitempty"`
	KeepLast      int    `json:"keep_last"`
	MaxTotalMB    int    `json:"max_total_mb"`
	RemoteOnWrite bool   `json:"remote_on_write"`
	Strict        bool   `json:"strict"`
}

type Settings struct {
	Backup BackupSettings `json:"backup"`
}

func DefaultSettings(p Paths) Settings {
	return Settings{
		Backup: BackupSettings{
			Enabled:       false,
			Mode:          BackupModeNone,
			LocalDir:      p.Backups,
			KeepLast:      10,
			MaxTotalMB:    50,
			RemoteOnWrite: true,
			Strict:        false,
		},
	}
}

func LoadSettings(p Paths) (Settings, error) {
	s := DefaultSettings(p)
	b, err := os.ReadFile(p.Settings)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	applyDefaults(&s, p)
	return s, nil
}

func applyDefaults(s *Settings, p Paths) {
	if s.Backup.Mode == "" {
		s.Backup.Mode = BackupModeNone
	}
	if s.Backup.LocalDir == "" {
		s.Backup.LocalDir = p.Backups
	}
	if s.Backup.KeepLast <= 0 {
		s.Backup.KeepLast = 10
	}
	if s.Backup.MaxTotalMB < 0 {
		s.Backup.MaxTotalMB = 50
	}
}

func SaveSettings(p Paths, s Settings) error {
	applyDefaults(&s, p)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return WriteAtomic(p.Settings, b, 0o600)
}

func (s Settings) BackupEnabled() bool {
	return s.Backup.Enabled && s.Backup.Mode != BackupModeNone
}

func (s Settings) HasLocal() bool {
	return s.BackupEnabled() && (s.Backup.Mode == BackupModeLocal || s.Backup.Mode == BackupModeLocalRemote)
}

func (s Settings) HasRemote() bool {
	return s.BackupEnabled() && (s.Backup.Mode == BackupModeRemote || s.Backup.Mode == BackupModeLocalRemote)
}
