package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"fvault/internal/backup"
	"fvault/internal/config"
	"fvault/internal/crypto"
)

func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Manage encrypted backups",
	}
	cmd.AddCommand(
		newBackupSetupCmd(),
		newBackupConfigCmd(),
		newBackupStatusCmd(),
		newBackupCreateCmd(),
		newBackupListCmd(),
		newBackupSyncCmd(),
		newBackupPruneCmd(),
		newBackupVerifyCmd(),
		newBackupRestoreCmd(),
		newBackupExportCmd(),
	)
	return cmd
}

func newBackupSetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Configure automatic backups",
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
			if err := setupBackupInteractive(p, &s); err != nil {
				return err
			}
			fmt.Printf("[OK] Backup settings saved to %s\n", p.Settings)
			return nil
		},
	}
}

func newBackupConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or change backup settings",
	}
	cmd.AddCommand(newBackupConfigShowCmd(), newBackupConfigSetCmd())
	return cmd
}

func newBackupConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show backup settings",
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
			b, err := json.MarshalIndent(s.Backup, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		},
	}
}

func newBackupConfigSetCmd() *cobra.Command {
	var mode, localDir, remoteDir string
	var keep, maxSize int
	var remoteOnWrite, strict bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Change backup settings",
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
			if cmd.Flags().Changed("mode") {
				switch mode {
				case config.BackupModeNone, config.BackupModeLocal, config.BackupModeLocalRemote, config.BackupModeRemote:
					s.Backup.Mode = mode
				default:
					return fmt.Errorf("invalid mode %q", mode)
				}
			}
			if cmd.Flags().Changed("local-dir") {
				abs, err := filepath.Abs(localDir)
				if err != nil {
					return err
				}
				s.Backup.LocalDir = abs
			}
			if cmd.Flags().Changed("remote-dir") {
				abs, err := filepath.Abs(remoteDir)
				if err != nil {
					return err
				}
				s.Backup.RemoteDir = abs
				s.Backup.RemoteMarker = ""
			}
			if cmd.Flags().Changed("keep") {
				if keep < 1 {
					return errors.New("--keep must be at least 1")
				}
				s.Backup.KeepLast = keep
			}
			if cmd.Flags().Changed("max-size") {
				if maxSize < 0 {
					return errors.New("--max-size cannot be negative")
				}
				s.Backup.MaxTotalMB = maxSize
			}
			if cmd.Flags().Changed("remote-on-write") {
				s.Backup.RemoteOnWrite = remoteOnWrite
			}
			if cmd.Flags().Changed("strict") {
				s.Backup.Strict = strict
			}
			if s.Backup.Mode == config.BackupModeNone {
				s.Backup.Enabled = false
			} else {
				s.Backup.Enabled = true
			}
			if s.Backup.LocalDir == "" {
				s.Backup.LocalDir = p.Backups
			}
			if s.HasRemote() {
				if s.Backup.RemoteDir == "" {
					return errors.New("remote mode requires --remote-dir")
				}
				if s.Backup.RemoteMarker == "" {
					b, err := crypto.RandomBytes(16)
					if err != nil {
						return err
					}
					s.Backup.RemoteMarker = hex.EncodeToString(b)
				}
				bm := backup.New(p, s)
				if err := bm.EnsureRemote(s.Backup.RemoteMarker); err != nil {
					return err
				}
			}
			if err := config.SaveSettings(p, s); err != nil {
				return err
			}
			fmt.Println("[OK] Backup settings updated.")
			return nil
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "", "none, local, local+remote, or remote")
	cmd.Flags().StringVar(&localDir, "local-dir", "", "local backup folder")
	cmd.Flags().StringVar(&remoteDir, "remote-dir", "", "mounted remote backup folder")
	cmd.Flags().IntVar(&keep, "keep", 0, "number of snapshots to keep")
	cmd.Flags().IntVar(&maxSize, "max-size", 0, "maximum total size in MB (0 = unlimited)")
	cmd.Flags().BoolVar(&remoteOnWrite, "remote-on-write", false, "copy to remote after every write")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat remote failures as errors")
	return cmd
}

func newBackupStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show backup status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, s, err := settingsForBackup()
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			st := bm.Status()
			fmt.Printf("Backup    : %s (enabled=%v)\n", st.Mode, st.Enabled)
			fmt.Printf("Local     : %s (%d snapshots, %s)\n", st.LocalDir, st.LocalCount, humanBytes(st.LocalBytes))
			if s.HasRemote() {
				state := "OK"
				if !st.RemoteOK {
					state = "UNAVAILABLE: " + st.RemoteError
				}
				fmt.Printf("Remote    : %s (%d snapshots, %s) [%s]\n", st.RemoteDir, st.RemoteCount, humanBytes(st.RemoteBytes), state)
			} else {
				fmt.Println("Remote    : not configured")
			}
			fmt.Printf("Retention : %d snapshots / %d MB\n", st.KeepLast, st.MaxTotalMB)
			if st.Latest != "" {
				fmt.Printf("Latest    : %s\n", st.Latest)
			}
			if st.RemoteMarker != "" {
				fmt.Printf("Marker    : %s\n", st.RemoteMarker)
			}
			return nil
		},
	}
}

func newBackupCreateCmd() *cobra.Command {
	var label string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a snapshot now",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, s, err := settingsForBackup()
			if err != nil {
				return err
			}
			v, err := openVault(p)
			if err != nil {
				return err
			}
			if label == "" {
				label = "manual"
			}
			bm := backup.New(p, s)
			res, err := bm.Create(v.Path, label)
			if err != nil {
				return err
			}
			if !s.BackupEnabled() {
				fmt.Println("[i] Backups are disabled.")
				return nil
			}
			if res.Path == "" {
				fmt.Println("[i] No new snapshot was needed.")
				return nil
			}
			fmt.Printf("[OK] Snapshot created: %s\n", res.Path)
			if res.Warning != "" {
				fmt.Printf("[WARN] %s\n", res.Warning)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "snapshot label")
	return cmd
}

func newBackupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List snapshots",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, s, err := settingsForBackup()
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			records, err := bm.List()
			if err != nil {
				return err
			}
			if len(records) == 0 {
				fmt.Println("No snapshots found.")
				return nil
			}
			fmt.Printf("%-3s %-42s %-8s %-20s %s\n", "No", "File", "Size", "Time", "Location")
			for i, r := range records {
				location := ""
				if r.Local {
					location = "local"
				}
				if r.Remote {
					if location != "" {
						location += ", remote"
					} else {
						location = "remote"
					}
				}
				fmt.Printf("%-3d %-42s %-8s %-20s %s\n", i+1, r.Name, humanBytes(r.Size), r.ModTime.Local().Format("2006-01-02 15:04"), location)
			}
			return nil
		},
	}
}

func newBackupSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Copy local snapshots to the remote folder",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, s, err := settingsForBackup()
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			n, err := bm.Sync()
			if err != nil {
				return err
			}
			fmt.Printf("[OK] %d snapshots synced to %s\n", n, s.Backup.RemoteDir)
			return nil
		},
	}
}

func newBackupPruneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "prune",
		Short: "Enforce snapshot retention",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, s, err := settingsForBackup()
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			if err := bm.PruneDir(s.Backup.LocalDir); err != nil {
				return err
			}
			if s.HasRemote() {
				if err := bm.PruneDir(s.Backup.RemoteDir); err != nil {
					return err
				}
			}
			fmt.Println("[OK] Retention applied.")
			return nil
		},
	}
}

func newBackupVerifyCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "verify [file]",
		Short: "Verify snapshots can be decrypted",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, s, err := settingsForBackup()
			if err != nil {
				return err
			}
			password, err := promptPassword("Master Password")
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			if all {
				results, err := bm.VerifyAll(password)
				if err != nil {
					return err
				}
				var best string
				failures := 0
				for _, r := range results {
					if r.OK {
						fmt.Printf("[OK]   %-42s (%d folders, %d entries)\n", r.Name, r.Folders, r.Entries)
						if best == "" {
							best = r.Path
						}
					} else {
						failures++
						fmt.Printf("[FAIL] %-42s %s\n", r.Name, r.Error)
					}
				}
				if best != "" {
					fmt.Printf("\nBest backup: %s\n", best)
				}
				if failures == len(results) {
					return errors.New("no backup could be decrypted")
				}
				return nil
			}
			if len(args) == 0 {
				return errors.New("provide a backup file or use --all")
			}
			res, err := bm.Verify(args[0], password)
			if err != nil {
				return err
			}
			if !res.OK {
				return fmt.Errorf("verification failed: %s", res.Error)
			}
			fmt.Printf("[OK] %s (%d folders, %d entries)\n", res.Path, res.Folders, res.Entries)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "verify all local snapshots")
	return cmd
}

func newBackupRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <file|latest>",
		Short: "Restore a snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, s, err := settingsForBackup()
			if err != nil {
				return err
			}
			password, err := promptPassword("Master Password")
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			source := args[0]
			if source == "latest" {
				source, err = bm.Latest()
				if err != nil {
					return err
				}
			}
			res, err := bm.Verify(source, password)
			if err != nil {
				return err
			}
			if !res.OK {
				return fmt.Errorf("backup cannot be decrypted: %s", res.Error)
			}
			fmt.Printf("[OK] Backup verified (%d folders, %d entries)\n", res.Folders, res.Entries)
			value, err := readLine("This will replace the current vault. Type RESTORE to continue: ")
			if err != nil {
				return err
			}
			if strings.TrimSpace(value) != "RESTORE" {
				fmt.Println("Cancelled.")
				return nil
			}
			if err := bm.Restore(source, p.Vault, password); err != nil {
				return err
			}
			fmt.Println("[OK] Vault restored and verified.")
			return nil
		},
	}
}

func newBackupExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export <destination>",
		Short: "Export the encrypted vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, s, err := settingsForBackup()
			if err != nil {
				return err
			}
			password, err := promptPassword("Master Password")
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			dest, err := bm.Export(args[0], p.Vault, password)
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Encrypted vault exported to %s\n", dest)
			return nil
		},
	}
}

func settingsForBackup() (config.Paths, config.Settings, error) {
	p, err := resolvePaths()
	if err != nil {
		return config.Paths{}, config.Settings{}, err
	}
	s, err := loadSettings(p)
	if err != nil {
		return config.Paths{}, config.Settings{}, err
	}
	return p, s, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
