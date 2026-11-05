package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"fvault/internal/backup"
	"fvault/internal/config"
	"fvault/internal/crypto"
	"fvault/internal/vault"
)

func newStartCmd() *cobra.Command {
	var username string
	var noBackup bool
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Set up fvault if needed and open the CLI menu",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			if err := p.Ensure(); err != nil {
				return err
			}
			s, err := loadSettings(p)
			if err != nil {
				return err
			}

			var v *vault.Vault
			if _, statErr := os.Stat(p.Vault); errors.Is(statErr, os.ErrNotExist) {
				username = strings.TrimSpace(username)
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
				enableBackups := false
				if !noBackup {
					enableBackups, err = confirm("Enable automatic local backups?", true)
					if err != nil {
						return err
					}
				}

				var warning string
				v, s, warning, err = createVaultQuick(p, username, password, enableBackups)
				if err != nil {
					return err
				}
				fmt.Printf("\n[OK] Vault    : %s\n", p.Vault)
				fmt.Printf("[OK] Username : %s\n", username)
				if s.BackupEnabled() {
					fmt.Printf("[OK] Backups  : local -> %s\n", s.Backup.LocalDir)
				} else {
					fmt.Println("[i]  Backups  : disabled (run 'fvault backup setup' later)")
				}
				if warning != "" {
					fmt.Printf("[WARN] %s\n", warning)
				}
				fmt.Println("[i]  Master Password is NOT stored. Do not forget it.")
				fmt.Println()
			} else if statErr != nil {
				return statErr
			} else {
				v, err = openVault(p)
				if err != nil {
					return err
				}
			}

			return runMenuWithVault(p, s, v)
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "web login username (asked when creating the vault)")
	cmd.Flags().BoolVar(&noBackup, "no-backup", false, "disable automatic local backups during setup")
	return cmd
}

func createVaultQuick(p config.Paths, username, password string, enableBackups bool) (*vault.Vault, config.Settings, string, error) {
	if err := p.Ensure(); err != nil {
		return nil, config.Settings{}, "", err
	}
	if _, err := config.EnsureSecret(p.Secret); err != nil {
		return nil, config.Settings{}, "", err
	}
	v, err := vault.Create(p.Vault, password, username, crypto.DefaultParams())
	if err != nil {
		return nil, config.Settings{}, "", err
	}

	s := config.DefaultSettings(p)
	if enableBackups {
		s.Backup.Enabled = true
		s.Backup.Mode = config.BackupModeLocal
		s.Backup.LocalDir = p.Backups
		s.Backup.KeepLast = 10
		s.Backup.MaxTotalMB = 50
	} else {
		s.Backup.Enabled = false
		s.Backup.Mode = config.BackupModeNone
	}
	if err := config.SaveSettings(p, s); err != nil {
		return nil, config.Settings{}, "", err
	}

	warning := ""
	if enableBackups {
		res, err := backup.New(p, s).Create(v.Path, "init")
		if err != nil {
			warning = "initial backup failed: " + err.Error()
		} else {
			warning = res.Warning
		}
	}
	return v, s, warning, nil
}
