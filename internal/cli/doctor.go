package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"fvault/internal/backup"
	"fvault/internal/config"
	"fvault/internal/vault"
)

func newDoctorCmd() *cobra.Command {
	var noDecrypt bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check vault and backup health",
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
			return doctorReport(p, s, noDecrypt)
		},
	}
	cmd.Flags().BoolVar(&noDecrypt, "no-decrypt", false, "skip the Master Password decryption check")
	return cmd
}

func doctorReport(p config.Paths, s config.Settings, noDecrypt bool) error {
	failures := 0
	fmt.Printf("FVault doctor\n")
	fmt.Printf("Data directory: %s\n\n", p.Home)

	info, statErr := os.Stat(p.Vault)
	if statErr != nil {
		fmt.Printf("[FAIL] vault        : %v\n", statErr)
		failures++
	} else {
		fmt.Printf("[OK]   vault        : %s (%s)\n", p.Vault, humanBytes(info.Size()))
		if info.Mode().Perm()&0o077 != 0 {
			fmt.Printf("[WARN] vault perms  : %o (expected 600)\n", info.Mode().Perm())
		}
	}

	if _, err := os.Stat(p.Secret); err != nil {
		fmt.Printf("[FAIL] secret       : %v\n", err)
		failures++
	} else {
		fmt.Println("[OK]   secret       : present")
	}

	if statErr == nil {
		vi, err := vault.Inspect(p.Vault)
		if err != nil {
			fmt.Printf("[FAIL] vault format : %v\n", err)
			failures++
		} else {
			fmt.Printf("[OK]   vault format : version=%d kdf=%s t=%d m=%dKiB p=%d aead=%s\n",
				vi.Version, vi.KDFName, vi.Params.Time, vi.Params.MemoryKiB, vi.Params.Threads, vi.AEADName)
			if !noDecrypt {
				password, err := promptPassword("Master Password")
				if err != nil {
					return err
				}
				v, err := vault.Open(p.Vault, password)
				if err != nil {
					fmt.Printf("[FAIL] decrypt      : %v\n", err)
					failures++
				} else {
					fmt.Printf("[OK]   decrypt      : %d folders, %d entries\n", len(v.Payload.Folders), v.Payload.TotalEntries())
				}
			}
		}
	}

	fmt.Printf("[OK]   backup mode  : %s\n", s.Backup.Mode)
	bm := backup.New(p, s)
	st := bm.Status()
	if s.BackupEnabled() {
		fmt.Printf("[OK]   local backup : %s (%d snapshots, %s)\n", st.LocalDir, st.LocalCount, humanBytes(st.LocalBytes))
		if st.LocalCount == 0 {
			fmt.Println("[WARN] local backup : no snapshots yet")
		}
		if s.HasRemote() {
			if st.RemoteOK {
				fmt.Printf("[OK]   remote backup: %s (%d snapshots, %s)\n", st.RemoteDir, st.RemoteCount, humanBytes(st.RemoteBytes))
			} else {
				fmt.Printf("[WARN] remote backup: %s (%s)\n", st.RemoteDir, st.RemoteError)
			}
		}
	} else {
		fmt.Println("[WARN] backups      : disabled")
	}

	fmt.Println()
	if failures > 0 {
		return fmt.Errorf("%d check(s) failed", failures)
	}
	fmt.Println("[OK] All critical checks passed.")
	return nil
}
