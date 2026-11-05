package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"fvault/internal/config"
	"fvault/internal/recovery"
)

// renderEmergencyKit builds the printable emergency reference for a vault.
func renderEmergencyKit(p config.Paths, username string) string {
	var b strings.Builder
	b.WriteString("=================== FVAULT EMERGENCY KIT ===================\n\n")
	fmt.Fprintf(&b, "Vault file     : %s\n", p.Vault)
	fmt.Fprintf(&b, "Settings file  : %s\n", p.Settings)
	fmt.Fprintf(&b, "Backups dir    : %s\n", p.Backups)
	if username != "" {
		fmt.Fprintf(&b, "Web username   : %s\n", username)
	}
	b.WriteString("\nREMEMBER\n")
	b.WriteString("  * The Master Password is never stored anywhere.\n")
	if recovery.Configured(p.Recovery) {
		b.WriteString("  * Recovery is set up: reset with 'fvault recovery reset' (or the web login page).\n")
	} else {
		b.WriteString("  * There is no reset unless you set up security questions (fvault recovery setup).\n")
	}
	b.WriteString("  * Without it the vault file cannot be opened - not even a backup copy.\n")
	b.WriteString("  * Keep an offline copy of vault.json somewhere safe.\n")
	b.WriteString("  * Moving to a new PC:  fvault backup export <file>\n")
	b.WriteString("                        fvault backup restore <file>\n")
	b.WriteString("  * Full guide: README.md -> \"Moving to a new computer\".\n")
	b.WriteString("\n=============================================================\n")
	return b.String()
}

// saveEmergencyKit writes the kit to ~/fvault-emergency-kit.txt (mode 0600).
func saveEmergencyKit(p config.Paths, username string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(home, "fvault-emergency-kit.txt")
	if err := os.WriteFile(dest, []byte(renderEmergencyKit(p, username)), 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

// printEmergencyKit shows the kit after vault creation and offers saving it.
func printEmergencyKit(p config.Paths, username string, offerSave bool) {
	fmt.Print(renderEmergencyKit(p, username))
	if !offerSave {
		return
	}
	if ok, err := confirm("Save a copy to ~/fvault-emergency-kit.txt?", false); err == nil && ok {
		dest, err := saveEmergencyKit(p, username)
		if err != nil {
			fmt.Printf("[WARN] Could not save the kit: %v\n", err)
			return
		}
		fmt.Printf("[OK] Emergency kit saved to %s\n", dest)
	}
}

func newKitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "kit",
		Short: "Print the emergency kit for this vault",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			v, err := openVault(p)
			if err != nil {
				return err
			}
			printEmergencyKit(p, v.Payload.Meta.Username, true)
			return nil
		},
	}
}
