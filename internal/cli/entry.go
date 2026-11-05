package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fvault/internal/clipboard"
	"fvault/internal/config"
	"fvault/internal/vault"
)

func openVault(p config.Paths) (*vault.Vault, error) {
	if _, err := os.Stat(p.Vault); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("vault not found at %s; run 'fvault init' first", p.Vault)
	}
	password, err := promptPassword("Master Password")
	if err != nil {
		return nil, err
	}
	return vault.Open(p.Vault, password)
}

func clipboardClearSeconds() time.Duration {
	value := os.Getenv("FVAULT_CLIPBOARD_CLEAR_SECONDS")
	if value == "" {
		return 30 * time.Second
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 30 * time.Second
	}
	return time.Duration(n) * time.Second
}

func newAddCmd() *cobra.Command {
	var username, tags, templateName string
	var generate bool
	var length int
	var pinned bool
	cmd := &cobra.Command{
		Use:   "add <folder>/<name>",
		Short: "Add an entry",
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
			folder, name, err := vault.ParsePath(args[0])
			if err != nil {
				return err
			}
			if _, exists := v.Payload.GetEntry(folder, name); exists {
				return fmt.Errorf("entry %s/%s already exists", folder, name)
			}
			if templateName != "" {
				if defaults, ok := entryTemplates[templateName]; ok {
					if username == "" {
						username = defaults.Username
					}
					if !cmd.Flags().Changed("length") {
						length = defaults.Length
					}
				} else {
					return fmt.Errorf("unknown template %q", templateName)
				}
			}
			if username == "" {
				username, err = promptString("Username (optional)", "")
				if err != nil {
					return err
				}
			}
			if !cmd.Flags().Changed("tags") && tags == "" {
				tags, err = promptString("Tags (comma separated)", "")
				if err != nil {
					return err
				}
			}
			if !cmd.Flags().Changed("pinned") {
				pinned, err = confirm("Pinned/favorite?", false)
				if err != nil {
					return err
				}
			}
			var password string
			if generate {
				password, err = generatePassword(length)
				if err != nil {
					return err
				}
				fmt.Printf("[OK] Generated password: %s\n", password)
				fmt.Println("[i]  This is shown only once.")
			} else {
				for {
					password, err = readPassword("Password: ")
					if err != nil {
						return err
					}
					if password == "" {
						fmt.Println("Password cannot be empty.")
						continue
					}
					confirmPassword, err := readPassword("Confirm Password: ")
					if err != nil {
						return err
					}
					if password != confirmPassword {
						fmt.Println("Passwords do not match. Try again.")
						continue
					}
					break
				}
			}
			duplicates := v.Payload.DuplicateEntries(username, password, folder, name)
			if len(duplicates) > 0 {
				fmt.Println("[WARN] A similar entry already exists:")
				for _, dup := range duplicates {
					fmt.Printf("  - %s/%s\n", dup.Folder, dup.Name)
				}
			}
			tagList := splitTags(tags)
			entry := vault.Entry{Username: username, Password: password, Tags: tagList, Pinned: pinned}
			if err := v.Payload.AddEntry(folder, name, entry); err != nil {
				return err
			}
			res, err := commitVault(p, s, v, "add")
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Entry '%s/%s' saved.\n", folder, name)
			printBackupResult(res)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "entry username")
	cmd.Flags().StringVar(&tags, "tags", "", "comma separated tags")
	cmd.Flags().BoolVar(&pinned, "pinned", false, "mark the entry as pinned/favorite")
	cmd.Flags().StringVar(&templateName, "template", "", "entry template: server, database, api-token, ssh-key")
	cmd.Flags().BoolVar(&generate, "generate", false, "generate a random password")
	cmd.Flags().IntVar(&length, "length", 20, "generated password length")
	return cmd
}

func newGetCmd() *cobra.Command {
	var copyValue bool
	var field string
	var show bool
	cmd := &cobra.Command{
		Use:   "get <folder>/<name>",
		Short: "Show or copy an entry",
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
			folder, name, err := vault.ParsePath(args[0])
			if err != nil {
				return err
			}
			entry, ok := v.Payload.GetEntry(folder, name)
			if !ok {
				return fmt.Errorf("entry '%s/%s' not found", folder, name)
			}
			if copyValue {
				var value string
				switch field {
				case "password", "":
					value = entry.Password
				case "username":
					value = entry.Username
				default:
					return fmt.Errorf("invalid --field %q (use password or username)", field)
				}
				scheduled, err := clipboard.Copy(value, clipboardClearSeconds())
				if err != nil {
					return fmt.Errorf("could not copy to clipboard: %w", err)
				}
				fmt.Printf("[OK] %s for '%s/%s' copied.\n", strings.Title(fieldLabel(field)), folder, name)
				if scheduled {
					fmt.Println("[i]  Clipboard will be cleared in 30 seconds.")
				} else if clipboardClearSeconds() > 0 {
					fmt.Println("[i]  Automatic clipboard clearing is unavailable on this system.")
				}
				if !show {
					return nil
				}
			}
			fmt.Printf("Entry    : %s/%s\n", folder, name)
			fmt.Printf("Username : %s\n", entry.Username)
			fmt.Printf("Password : %s\n", entry.Password)
			if len(entry.Tags) > 0 {
				fmt.Printf("Tags     : %s\n", strings.Join(entry.Tags, ", "))
			}
			if entry.Pinned {
				fmt.Println("Pinned   : yes")
			}
			if len(entry.PasswordHistory) > 0 {
				fmt.Printf("History  : %d previous password(s)\n", len(entry.PasswordHistory))
			}
			fmt.Printf("Updated  : %s\n", entry.UpdatedAt)
			return nil
		},
	}
	cmd.Flags().BoolVar(&copyValue, "copy", false, "copy the value instead of printing it")
	cmd.Flags().StringVar(&field, "field", "password", "field to copy: password or username")
	cmd.Flags().BoolVar(&show, "show", false, "also print the entry when copying")
	return cmd
}

func fieldLabel(field string) string {
	if field == "" || field == "password" {
		return "password"
	}
	return field
}

func newListCmd() *cobra.Command {
	var folder string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List entries without passwords",
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
			var views []vault.EntryView
			if folder == "" {
				views = v.Payload.List()
			} else {
				if err := vault.ValidateName(folder); err != nil {
					return err
				}
				if _, ok := v.Payload.Folders[folder]; !ok {
					return fmt.Errorf("folder '%s' not found", folder)
				}
				views = v.Payload.Search("", folder)
			}
			if asJSON {
				b, err := json.MarshalIndent(views, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(b))
				return nil
			}
			lastFolder := ""
			for _, view := range views {
				if view.Folder != lastFolder {
					fmt.Printf("\n%s (%d)\n", view.Folder, v.Payload.FolderCount(view.Folder))
					lastFolder = view.Folder
				}
				prefix := "  "
				if view.Pinned {
					prefix = "* "
				}
				tags := "-"
				if len(view.Tags) > 0 {
					tags = strings.Join(view.Tags, ",")
				}
				fmt.Printf("%s%-16s %-16s %s\n", prefix, view.Name, view.Username, tags)
			}
			fmt.Printf("\nTotal: %d entries, %d folders\n", len(views), len(v.Payload.Folders))
			return nil
		},
	}
	cmd.Flags().StringVar(&folder, "folder", "", "only list this folder")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON (passwords are never included)")
	return cmd
}

func newSearchCmd() *cobra.Command {
	var folder string
	var copyValue bool
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search entries and optionally copy a password",
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
			results := v.Payload.Search(args[0], folder)
			if len(results) == 0 {
				fmt.Printf("No results for %q.\n", args[0])
				return nil
			}
			fmt.Printf("\nResults for %q (%d):\n", args[0], len(results))
			for i, r := range results {
				prefix := ""
				if r.Pinned {
					prefix = "* "
				}
				tags := ""
				if len(r.Tags) > 0 {
					tags = " [" + strings.Join(r.Tags, ",") + "]"
				}
				fmt.Printf("  [%d] %s%s/%s   %s%s\n", i+1, prefix, r.Folder, r.Name, r.Username, tags)
			}
			if !copyValue {
				fmt.Printf("\n[i] Copy: fvault search %q --copy\n", args[0])
				return nil
			}
			index := 0
			if len(results) > 1 {
				index, err = promptInt("Select [1-"+strconv.Itoa(len(results))+", q]", 1)
				if err != nil {
					return err
				}
				if index < 1 || index > len(results) {
					return errors.New("invalid selection")
				}
				index--
			}
			selected := results[index]
			entry, ok := v.Payload.GetEntry(selected.Folder, selected.Name)
			if !ok {
				return errors.New("selected entry no longer exists")
			}
			scheduled, err := clipboard.Copy(entry.Password, clipboardClearSeconds())
			if err != nil {
				return fmt.Errorf("could not copy to clipboard: %w", err)
			}
			fmt.Printf("[OK] Password for '%s/%s' copied.\n", selected.Folder, selected.Name)
			if scheduled {
				fmt.Println("[i]  Clipboard will be cleared in 30 seconds.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&folder, "folder", "", "only search this folder")
	cmd.Flags().BoolVar(&copyValue, "copy", false, "select a result and copy its password")
	return cmd
}

func newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <folder>/<name>",
		Short: "Delete an entry",
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
			folder, name, err := vault.ParsePath(args[0])
			if err != nil {
				return err
			}
			if _, ok := v.Payload.GetEntry(folder, name); !ok {
				return fmt.Errorf("entry '%s/%s' not found", folder, name)
			}
			yes, err := confirm(fmt.Sprintf("Delete '%s/%s'?", folder, name), false)
			if err != nil {
				return err
			}
			if !yes {
				fmt.Println("Cancelled.")
				return nil
			}
			if err := v.Payload.RemoveEntry(folder, name); err != nil {
				return err
			}
			res, err := commitVault(p, s, v, "remove")
			if err != nil {
				return err
			}
			fmt.Println("[OK] Entry deleted.")
			printBackupResult(res)
			return nil
		},
	}
	return cmd
}

var entryTemplates = map[string]struct {
	Username string
	Length   int
}{
	"server":    {Username: "root", Length: 24},
	"database":  {Username: "postgres", Length: 32},
	"api-token": {Username: "api", Length: 40},
	"ssh-key":   {Username: "git", Length: 32},
}

func splitTags(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}

func newEditCmd() *cobra.Command {
	var username, tags string
	var password string
	var generate bool
	var length int
	var pinned, unpin bool
	cmd := &cobra.Command{
		Use:   "edit <folder>/<name>",
		Short: "Edit an entry's username, tags, pinned state, or password",
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
			folder, name, err := vault.ParsePath(args[0])
			if err != nil {
				return err
			}
			entry, ok := v.Payload.GetEntry(folder, name)
			if !ok {
				return fmt.Errorf("entry '%s/%s' not found", folder, name)
			}

			if !cmd.Flags().Changed("username") {
				username, err = promptString("Username (optional)", entry.Username)
				if err != nil {
					return err
				}
			}
			if !cmd.Flags().Changed("tags") {
				tags, err = promptString("Tags (comma separated)", strings.Join(entry.Tags, ","))
				if err != nil {
					return err
				}
			}
			if !cmd.Flags().Changed("pinned") && !cmd.Flags().Changed("unpin") {
				pinned, err = confirm("Pinned/favorite?", entry.Pinned)
				if err != nil {
					return err
				}
			} else if cmd.Flags().Changed("unpin") {
				pinned = false
			}
			if generate {
				if length == 0 {
					length = 20
				}
				password, err = generatePassword(length)
				if err != nil {
					return err
				}
				fmt.Printf("[OK] Generated password: %s\n", password)
				fmt.Println("[i]  This is shown only once.")
			} else if !cmd.Flags().Changed("password") {
				password, err = readPassword("New password (blank to keep current): ")
				if err != nil {
					return err
				}
				if password != "" {
					confirmPassword, err := readPassword("Confirm new password: ")
					if err != nil {
						return err
					}
					if password != confirmPassword {
						return errors.New("passwords do not match")
					}
				}
			}
			if password == "" {
				password = entry.Password
			}
			duplicates := v.Payload.DuplicateEntries(username, password, folder, name)
			if len(duplicates) > 0 {
				fmt.Println("[WARN] A similar entry already exists:")
				for _, dup := range duplicates {
					fmt.Printf("  - %s/%s\n", dup.Folder, dup.Name)
				}
			}
			updated := vault.Entry{
				Username: username,
				Password: password,
				Tags:     splitTags(tags),
				Pinned:   pinned,
			}
			if err := v.Payload.UpdateEntry(folder, name, updated); err != nil {
				return err
			}
			res, err := commitVault(p, s, v, "update")
			if err != nil {
				return err
			}
			fmt.Printf("[OK] Entry '%s/%s' updated.\n", folder, name)
			printBackupResult(res)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "new entry username")
	cmd.Flags().StringVar(&tags, "tags", "", "comma separated tags")
	cmd.Flags().StringVar(&password, "password", "", "new password (blank keeps the current password)")
	cmd.Flags().BoolVar(&pinned, "pinned", false, "mark the entry as pinned/favorite")
	cmd.Flags().BoolVar(&unpin, "unpin", false, "remove the pinned/favorite mark")
	cmd.Flags().BoolVar(&generate, "generate", false, "generate a random password")
	cmd.Flags().IntVar(&length, "length", 20, "generated password length")
	return cmd
}

func (st *menuState) editEntry(folder, name string) {
	entry, ok := st.v.Payload.GetEntry(folder, name)
	if !ok {
		fmt.Println("Entry not found.")
		return
	}
	username, err := promptString("Username (optional)", entry.Username)
	if err != nil {
		return
	}
	tags, err := promptString("Tags (comma separated)", strings.Join(entry.Tags, ","))
	if err != nil {
		return
	}
	pinned, err := confirm("Pinned/favorite?", entry.Pinned)
	if err != nil {
		return
	}
	generate, _ := confirm("Generate a random password?", false)
	var password string
	if generate {
		password, err = generatePassword(20)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Printf("[OK] Generated password: %s\n", password)
		fmt.Println("[i]  This is shown only once.")
	} else {
		password, err = readPassword("New password (blank to keep current): ")
		if err != nil {
			return
		}
		if password != "" {
			confirmPassword, err := readPassword("Confirm new password: ")
			if err != nil {
				return
			}
			if password != confirmPassword {
				fmt.Println("Passwords do not match.")
				return
			}
		} else {
			password = entry.Password
		}
	}
	duplicates := st.v.Payload.DuplicateEntries(username, password, folder, name)
	if len(duplicates) > 0 {
		fmt.Println("[WARN] A similar entry already exists:")
		for _, dup := range duplicates {
			fmt.Printf("  - %s/%s\n", dup.Folder, dup.Name)
		}
	}
	updated := vault.Entry{
		Username: username,
		Password: password,
		Tags:     splitTags(tags),
		Pinned:   pinned,
	}
	if err := st.v.Payload.UpdateEntry(folder, name, updated); err != nil {
		fmt.Println("Error:", err)
		return
	}
	res, err := commitVault(st.p, st.s, st.v, "update")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("[OK] Entry '%s/%s' updated.\n", folder, name)
	printBackupResult(res)
}

func (st *menuState) editEntryPrompt() {
	path, err := promptRequired("Entry (folder/name)")
	if err != nil {
		return
	}
	folder, name, err := vault.ParsePath(path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if _, ok := st.v.Payload.GetEntry(folder, name); !ok {
		fmt.Println("Entry not found.")
		return
	}
	st.editEntry(folder, name)
}
