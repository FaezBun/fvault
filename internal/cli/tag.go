package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"fvault/internal/vault"
)

func newTagCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag",
		Short: "List, rename and delete tags",
	}
	cmd.AddCommand(
		newTagListCmd(),
		newTagRenameCmd(),
		newTagDeleteCmd(),
	)
	return cmd
}

func newTagListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every tag with its usage count",
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
			counts := v.Payload.TagCounts()
			if len(counts) == 0 {
				fmt.Println("No tags yet. Add tags when creating or editing an entry.")
				return nil
			}
			for _, t := range counts {
				word := "entries"
				if t.Count == 1 {
					word = "entry"
				}
				fmt.Printf("  %-24s %d %s\n", t.Name, t.Count, word)
			}
			fmt.Printf("\nTotal: %d tags\n", len(counts))
			return nil
		},
	}
}

func newTagRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a tag on every entry",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			oldName, newName := args[0], args[1]
			changed, err := v.Payload.RenameTag(oldName, newName)
			if err == vault.ErrNotFound {
				return fmt.Errorf("tag '%s' not found", oldName)
			}
			if err != nil {
				return err
			}
			res, err := commitVault(p, s, v, "tag-rename")
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Tag '%s' renamed to '%s' on %d entries.\n", oldName, newName, changed)
			printBackupResult(res)
			return nil
		},
	}
}

func newTagDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Remove a tag from every entry",
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
			v, err := openVault(p)
			if err != nil {
				return err
			}
			name := args[0]
			count := 0
			for _, t := range v.Payload.TagCounts() {
				if t.Name == name {
					count = t.Count
					break
				}
			}
			if count == 0 {
				return fmt.Errorf("tag '%s' not found", name)
			}
			word := "entries"
			if count == 1 {
				word = "entry"
			}
			ok, err := confirm(fmt.Sprintf("Remove tag '%s' from %d %s?", name, count, word), false)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Println("Cancelled.")
				return nil
			}
			removed, err := v.Payload.DeleteTag(name)
			if err != nil {
				return err
			}
			res, err := commitVault(p, s, v, "tag-delete")
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Tag '%s' removed from %d entries.\n", name, removed)
			printBackupResult(res)
			return nil
		},
	}
}
