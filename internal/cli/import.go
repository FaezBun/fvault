package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"fvault/internal/importer"
	"fvault/internal/vault"
)

func newImportCmd() *cobra.Command {
	var folder string
	var dryRun bool
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "import-md <file.md>",
		Short: "Import entries from a Markdown file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			s, err := loadSettings(p)
			if err != nil {
				return err
			}
			if folder == "" {
				folder = vault.DefaultFolder
			}
			if err := vault.ValidateName(folder); err != nil {
				return err
			}
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			entries, warnings, err := importer.Parse(f)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				fmt.Printf("[WARN] line %d: %s\n", w.Line, w.Message)
			}
			if len(entries) == 0 {
				fmt.Println("No importable entries found.")
				return nil
			}
			fmt.Printf("\nFound %d entries:\n", len(entries))
			for i, e := range entries {
				fmt.Printf("  %d. %-16s username=%-16s password=%s\n", i+1, e.Name, e.Username, importer.Mask(e.Password))
			}
			if dryRun {
				fmt.Println("\n[DRY-RUN] No changes were made.")
				return nil
			}
			yes, err := confirm(fmt.Sprintf("Import these entries into '%s'?", folder), false)
			if err != nil {
				return err
			}
			if !yes {
				fmt.Println("Cancelled.")
				return nil
			}
			v, err := openVault(p)
			if err != nil {
				return err
			}
			if err := v.Payload.EnsureFolder(folder); err != nil {
				return err
			}
			added, updated, skipped := 0, 0, 0
			for _, e := range entries {
				if err := vault.ValidateName(e.Name); err != nil {
					fmt.Printf("[WARN] skipping %q: invalid name\n", e.Name)
					skipped++
					continue
				}
				entry := vault.Entry{Username: e.Username, Password: e.Password, URL: e.URL, Notes: e.Notes}
				_, exists := v.Payload.GetEntry(folder, e.Name)
				if exists {
					if !overwrite {
						fmt.Printf("[SKIP] %s/%s already exists (use --overwrite)\n", folder, e.Name)
						skipped++
						continue
					}
					if err := v.Payload.UpdateEntry(folder, e.Name, entry); err != nil {
						fmt.Printf("[WARN] could not update %s/%s: %v\n", folder, e.Name, err)
						skipped++
						continue
					}
					updated++
					continue
				}
				if err := v.Payload.AddEntry(folder, e.Name, entry); err != nil {
					fmt.Printf("[WARN] could not add %s/%s: %v\n", folder, e.Name, err)
					skipped++
					continue
				}
				added++
			}
			if added+updated == 0 {
				fmt.Println("No entries were imported.")
				return nil
			}
			res, err := commitVault(p, s, v, "import")
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Imported %d new, updated %d, skipped %d.\n", added, updated, skipped)
			printBackupResult(res)
			fmt.Println("[i]  Delete the original .md file once you have verified the import.")
			return nil
		},
	}
	cmd.Flags().StringVar(&folder, "folder", vault.DefaultFolder, "destination folder")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without changing the vault")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite entries that already exist")
	return cmd
}
