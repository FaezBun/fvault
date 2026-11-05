package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"fvault/internal/importer"
	"fvault/internal/vault"
)

func newImportCSVCommand() *cobra.Command {
	var folder string
	var dryRun, overwrite bool
	cmd := &cobra.Command{
		Use:   "import-csv <file.csv>",
		Short: "Import entries from a CSV file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImportFile(args[0], folder, dryRun, overwrite, importer.ParseCSV)
		},
	}
	cmd.Flags().StringVar(&folder, "folder", vault.DefaultFolder, "destination folder")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without changing the vault")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite entries that already exist")
	return cmd
}

func newExportCSVCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "export-csv <file.csv>",
		Short: "Export entries to a CSV file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			v, err := openVault(p)
			if err != nil {
				return err
			}
			entries := make([]importer.Entry, 0)
			for _, view := range v.Payload.List() {
				entry, ok := v.Payload.GetEntry(view.Folder, view.Name)
				if !ok {
					continue
				}
				entries = append(entries, importer.Entry{
					Folder:   view.Folder,
					Name:     view.Name,
					Username: entry.Username,
					Password: entry.Password,
					Tags:     entry.Tags,
					Pinned:   entry.Pinned,
				})
			}
			f, err := os.Create(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			if err := importer.WriteCSV(f, entries); err != nil {
				return err
			}
			fmt.Printf("[OK] Exported %d entries to %s\\n", len(entries), args[0])
			return nil
		},
	}
}

func newImportJSONCommand() *cobra.Command {
	var folder string
	var dryRun, overwrite bool
	cmd := &cobra.Command{
		Use:   "import-json <file.json>",
		Short: "Import entries from a JSON file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImportFile(args[0], folder, dryRun, overwrite, importer.ParseJSON)
		},
	}
	cmd.Flags().StringVar(&folder, "folder", vault.DefaultFolder, "destination folder")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without changing the vault")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite entries that already exist")
	return cmd
}

func newExportJSONCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "export-json <file.json>",
		Short: "Export entries to a JSON file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			v, err := openVault(p)
			if err != nil {
				return err
			}
			entries := make([]importer.Entry, 0)
			for _, view := range v.Payload.List() {
				entry, ok := v.Payload.GetEntry(view.Folder, view.Name)
				if !ok {
					continue
				}
				entries = append(entries, importer.Entry{
					Folder:   view.Folder,
					Name:     view.Name,
					Username: entry.Username,
					Password: entry.Password,
					Tags:     entry.Tags,
					Pinned:   entry.Pinned,
				})
			}
			f, err := os.Create(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			if err := importer.WriteJSON(f, entries); err != nil {
				return err
			}
			fmt.Printf("[OK] Exported %d entries to %s\\n", len(entries), args[0])
			return nil
		},
	}
}

func newImportBitwardenCommand() *cobra.Command {
	var folder string
	var dryRun, overwrite bool
	cmd := &cobra.Command{
		Use:   "import-bitwarden <export.json>",
		Short: "Import entries from a Bitwarden JSON export",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			entries, warnings, err := importer.ParseBitwarden(f)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				fmt.Printf("[WARN] line %d: %s\\n", w.Line, w.Message)
			}
			for i := range entries {
				if entries[i].Folder == "" {
					entries[i].Folder = folder
				}
			}
			return runImportEntries(entries, folder, dryRun, overwrite)
		},
	}
	cmd.Flags().StringVar(&folder, "folder", vault.DefaultFolder, "destination folder for entries without a Bitwarden folder")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without changing the vault")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite entries that already exist")
	return cmd
}

func newImportOnePasswordCommand() *cobra.Command {
	var folder string
	var dryRun, overwrite bool
	cmd := &cobra.Command{
		Use:   "import-1password <export.csv>",
		Short: "Import entries from a 1Password CSV export",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			entries, warnings, err := importer.ParseOnePasswordCSV(f)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				fmt.Printf("[WARN] line %d: %s\\n", w.Line, w.Message)
			}
			for i := range entries {
				if entries[i].Folder == "" {
					entries[i].Folder = folder
				}
			}
			return runImportEntries(entries, folder, dryRun, overwrite)
		},
	}
	cmd.Flags().StringVar(&folder, "folder", vault.DefaultFolder, "destination folder")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without changing the vault")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite entries that already exist")
	return cmd
}

func runImportFile(path, folder string, dryRun, overwrite bool, parse func(io.Reader) ([]importer.Entry, []importer.Warning, error)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, warnings, err := parse(f)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Printf("[WARN] line %d: %s\\n", w.Line, w.Message)
	}
	for i := range entries {
		if entries[i].Folder == "" {
			entries[i].Folder = folder
		}
	}
	return runImportEntries(entries, folder, dryRun, overwrite)
}

func runImportEntries(entries []importer.Entry, folder string, dryRun, overwrite bool) error {
	if len(entries) == 0 {
		fmt.Println("No importable entries found.")
		return nil
	}
	fmt.Printf("\\nFound %d entries:\\n", len(entries))
	for i, e := range entries {
		fmt.Printf("  %d. %-16s username=%-16s password=%s\\n", i+1, e.Name, e.Username, importer.Mask(e.Password))
	}
	if dryRun {
		fmt.Println("\\n[DRY-RUN] No changes were made.")
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
	p, err := resolvePaths()
	if err != nil {
		return err
	}
	s, err := loadSettings(p)
	if err != nil {
		return err
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
			fmt.Printf("[WARN] skipping %q: invalid name\\n", e.Name)
			skipped++
			continue
		}
		destFolder := e.Folder
		if destFolder == "" {
			destFolder = folder
		}
		if err := vault.ValidateName(destFolder); err != nil {
			fmt.Printf("[WARN] skipping %q: invalid folder %q\\n", e.Name, destFolder)
			skipped++
			continue
		}
		if err := v.Payload.EnsureFolder(destFolder); err != nil {
			fmt.Printf("[WARN] could not create folder %s: %v\\n", destFolder, err)
			skipped++
			continue
		}
		entry := vault.Entry{
			Username: e.Username,
			Password: e.Password,
			Tags:     e.Tags,
			Pinned:   e.Pinned,
		}
		_, exists := v.Payload.GetEntry(destFolder, e.Name)
		if exists {
			if !overwrite {
				fmt.Printf("[SKIP] %s/%s already exists (use --overwrite)\\n", destFolder, e.Name)
				skipped++
				continue
			}
			if err := v.Payload.UpdateEntry(destFolder, e.Name, entry); err != nil {
				fmt.Printf("[WARN] could not update %s/%s: %v\\n", destFolder, e.Name, err)
				skipped++
				continue
			}
			updated++
			continue
		}
		if err := v.Payload.AddEntry(destFolder, e.Name, entry); err != nil {
			fmt.Printf("[WARN] could not add %s/%s: %v\\n", destFolder, e.Name, err)
			skipped++
			continue
		}
		added++
	}
	if added+updated == 0 {
		fmt.Println("No entries were imported.")
		return nil
	}
	v.Payload.RecordAudit("entry.import", folder, fmt.Sprintf("%d new, %d updated", added, updated))
	res, err := commitVault(p, s, v, "import")
	if err != nil {
		return err
	}
	fmt.Printf("[OK] Imported %d new, updated %d, skipped %d.\\n", added, updated, skipped)
	printBackupResult(res)
	return nil
}
