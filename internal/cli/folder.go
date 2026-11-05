package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"fvault/internal/vault"
)

func newFolderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "folder",
		Short: "Manage folders",
	}
	cmd.AddCommand(newFolderAddCmd(), newFolderListCmd(), newFolderRemoveCmd(), newFolderRenameCmd())
	return cmd
}

func newFolderAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <name>",
		Short: "Create a folder",
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
			if err := vault.ValidateName(name); err != nil {
				return err
			}
			if _, ok := v.Payload.Folders[name]; ok {
				return fmt.Errorf("folder '%s' already exists", name)
			}
			if err := v.Payload.EnsureFolder(name); err != nil {
				return err
			}
			res, err := commitVault(p, s, v, "folder-add")
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Folder '%s' created.\n", name)
			printBackupResult(res)
			return nil
		},
	}
}

func newFolderListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List folders",
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
			fmt.Println("Folders:")
			for _, name := range v.Payload.FolderNames() {
				fmt.Printf("  %-16s (%d)\n", name, v.Payload.FolderCount(name))
			}
			return nil
		},
	}
}

func newFolderRemoveCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Delete a folder",
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
			if name == vault.DefaultFolder {
				return vault.ErrDefaultFolder
			}
			if _, ok := v.Payload.Folders[name]; !ok {
				return fmt.Errorf("folder '%s' not found", name)
			}
			count := v.Payload.FolderCount(name)
			if count > 0 && !force {
				return errors.New("folder is not empty; use --force to delete it and its entries")
			}
			if force && count > 0 {
				value, err := readLine(fmt.Sprintf("Folder '%s' has %d entries. Type DELETE to continue: ", name, count))
				if err != nil {
					return err
				}
				if strings.TrimSpace(value) != "DELETE" {
					fmt.Println("Cancelled.")
					return nil
				}
			}
			if err := v.Payload.RemoveFolder(name, force); err != nil {
				return err
			}
			res, err := commitVault(p, s, v, "folder-remove")
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Folder '%s' deleted.\n", name)
			printBackupResult(res)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete the folder and all of its entries")
	return cmd
}

func newFolderRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a folder",
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
			if oldName == vault.DefaultFolder {
				return vault.ErrDefaultFolder
			}
			if err := vault.ValidateName(oldName); err != nil {
				return err
			}
			if err := vault.ValidateName(newName); err != nil {
				return err
			}
			if _, ok := v.Payload.Folders[oldName]; !ok {
				return fmt.Errorf("folder '%s' not found", oldName)
			}
			if err := v.Payload.RenameFolder(oldName, newName); err != nil {
				return err
			}
			res, err := commitVault(p, s, v, "folder-rename")
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Folder '%s' renamed to '%s'.\n", oldName, newName)
			printBackupResult(res)
			return nil
		},
	}
}
