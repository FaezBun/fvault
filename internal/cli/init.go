package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"fvault/internal/backup"
	"fvault/internal/config"
	"fvault/internal/crypto"
	"fvault/internal/vault"
)

func newInitCmd() *cobra.Command {
	var username string
	var noBackup bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the vault and configure backups",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			if err := p.Ensure(); err != nil {
				return err
			}
			if _, err := os.Stat(p.Vault); err == nil {
				return fmt.Errorf("vault already exists at %s", p.Vault)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if username == "" {
				username, err = promptRequired("Username")
				if err != nil {
					return err
				}
			}
			password, err := promptNewPassword()
			if err != nil {
				return err
			}
			if _, err := config.EnsureSecret(p.Secret); err != nil {
				return err
			}
			if _, err := vault.Create(p.Vault, password, username, crypto.DefaultParams()); err != nil {
				return err
			}

			settings := config.DefaultSettings(p)
			if noBackup {
				settings.Backup.Enabled = false
				settings.Backup.Mode = config.BackupModeNone
			} else {
				if err := setupBackupInteractive(p, &settings); err != nil {
					return err
				}
			}
			if err := config.SaveSettings(p, settings); err != nil {
				return err
			}

			fmt.Printf("\n[OK] Vault    : %s\n", p.Vault)
			fmt.Printf("[OK] Secret   : %s\n", p.Secret)
			fmt.Printf("[OK] Settings : %s\n", p.Settings)
			fmt.Println("[i]  Master Password is NOT stored. Do not forget it.")
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "web login username")
	cmd.Flags().BoolVar(&noBackup, "no-backup", false, "disable automatic backups")
	return cmd
}

func setupBackupInteractive(p config.Paths, s *config.Settings) error {
	enable, err := confirm("Enable automatic backups?", true)
	if err != nil {
		return err
	}
	if !enable {
		s.Backup.Enabled = false
		s.Backup.Mode = config.BackupModeNone
		if s.Backup.LocalDir == "" {
			s.Backup.LocalDir = p.Backups
		}
		if s.Backup.KeepLast <= 0 {
			s.Backup.KeepLast = 10
		}
		if s.Backup.MaxTotalMB < 0 {
			s.Backup.MaxTotalMB = 50
		}
		fmt.Println("[OK] Automatic backups are disabled.")
		return config.SaveSettings(p, *s)
	}

	fmt.Println("\n  1) Local only")
	fmt.Println("  2) Local + remote folder (recommended)")
	fmt.Println("  3) Remote only")
	fmt.Println("  4) No backups")
	choice, err := promptInt("Select [1-4]", 2)
	if err != nil {
		return err
	}
	switch choice {
	case 1:
		s.Backup.Mode = config.BackupModeLocal
	case 2:
		s.Backup.Mode = config.BackupModeLocalRemote
	case 3:
		s.Backup.Mode = config.BackupModeRemote
	case 4:
		s.Backup.Enabled = false
		s.Backup.Mode = config.BackupModeNone
		s.Backup.RemoteDir = ""
		s.Backup.RemoteMarker = ""
		return config.SaveSettings(p, *s)
	default:
		return errors.New("invalid selection")
	}
	s.Backup.Enabled = true

	localDefault := s.Backup.LocalDir
	if localDefault == "" {
		localDefault = p.Backups
	}
	localDir, err := promptString("Local folder", localDefault)
	if err != nil {
		return err
	}
	localDir, err = filepath.Abs(localDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		return err
	}
	s.Backup.LocalDir = localDir

	if s.Backup.Mode == config.BackupModeRemote || s.Backup.Mode == config.BackupModeLocalRemote {
		remoteDir, err := promptString("Remote folder", s.Backup.RemoteDir)
		if err != nil {
			return err
		}
		if remoteDir == "" {
			return errors.New("remote folder is required")
		}
		remoteDir, err = filepath.Abs(remoteDir)
		if err != nil {
			return err
		}
		s.Backup.RemoteDir = remoteDir

		marker := s.Backup.RemoteMarker
		if marker == "" {
			b, err := crypto.RandomBytes(16)
			if err != nil {
				return err
			}
			marker = hex.EncodeToString(b)
		}
		bm := backup.New(p, *s)
		if err := bm.EnsureRemote(marker); err != nil {
			return err
		}
		s.Backup.RemoteMarker = marker
		if err := testWrite(remoteDir); err != nil {
			return fmt.Errorf("remote folder is not writable: %w", err)
		}
		fmt.Println("[OK] Remote folder is writable (marker saved).")
	} else {
		s.Backup.RemoteDir = ""
		s.Backup.RemoteMarker = ""
	}

	keep, err := promptInt("Keep snapshots", defaultInt(s.Backup.KeepLast, 10))
	if err != nil {
		return err
	}
	if keep < 1 {
		keep = 1
	}
	s.Backup.KeepLast = keep

	maxMB, err := promptInt("Storage limit MB (0 = unlimited)", defaultInt(s.Backup.MaxTotalMB, 50))
	if err != nil {
		return err
	}
	if maxMB < 0 {
		maxMB = 0
	}
	s.Backup.MaxTotalMB = maxMB

	remoteOnWrite, err := confirm("Copy to remote after every write?", true)
	if err != nil {
		return err
	}
	s.Backup.RemoteOnWrite = remoteOnWrite

	return config.SaveSettings(p, *s)
}

func defaultInt(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func testWrite(dir string) error {
	f, err := os.CreateTemp(dir, ".fvault-write-test-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if _, err := f.WriteString("ok"); err != nil {
		f.Close()
		os.Remove(name)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Remove(name)
}
