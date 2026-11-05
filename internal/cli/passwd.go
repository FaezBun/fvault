package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"fvault/internal/backup"
	"fvault/internal/crypto"
	"fvault/internal/vault"
)

func newPasswdCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd",
		Short: "Change the Master Password",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			s, err := loadSettings(p)
			if err != nil {
				return err
			}
			oldPassword, err := promptPassword("Current Master Password")
			if err != nil {
				return err
			}
			v, err := vault.Open(p.Vault, oldPassword)
			if err != nil {
				return err
			}
			newPassword, err := newPasswordConfirmed()
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			if _, err := bm.Create(v.Path, "pre-passwd"); err != nil {
				fmt.Printf("[WARN] Could not create a pre-change snapshot: %v\n", err)
			}
			if err := v.Rekey(newPassword, crypto.DefaultParams()); err != nil {
				return err
			}
			v.Payload.RecordAudit("vault.rekey", "", "master password changed")
			res, err := bm.Create(v.Path, "passwd")
			if err != nil {
				return err
			}
			fmt.Println("[OK] Master Password changed and vault re-encrypted.")
			printBackupResult(res)
			return nil
		},
	}
}

func newPasswordConfirmed() (string, error) {
	for {
		first, err := readPassword("New Master Password: ")
		if err != nil {
			return "", err
		}
		if len(first) < 8 {
			fmt.Println("Master Password must be at least 8 characters.")
			continue
		}
		second, err := readPassword("Confirm New Master Password: ")
		if err != nil {
			return "", err
		}
		if first != second {
			fmt.Println("Passwords do not match. Try again.")
			continue
		}
		if len(first) < 12 {
			fmt.Println("Note: 12+ characters is recommended.")
		}
		return first, nil
	}
}
