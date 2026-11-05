package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"fvault/internal/backup"
	"fvault/internal/clipboard"
	"fvault/internal/config"
	"fvault/internal/crypto"
	"fvault/internal/vault"
	"fvault/internal/web"
)

type menuState struct {
	p  config.Paths
	s  config.Settings
	v  *vault.Vault
	bm *backup.Manager
}

func newMenuCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "menu",
		Short: "Open the interactive menu",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMenu()
		},
	}
}

func runMenu() error {
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
	return runMenuWithVault(p, s, v)
}

func runMenuWithVault(p config.Paths, s config.Settings, v *vault.Vault) error {
	st := &menuState{p: p, s: s, v: v, bm: backup.New(p, s)}
	for {
		fmt.Println()
		fmt.Println("┌────────────────────────────────────────────┐")
		fmt.Println("│  FVault — Encrypted Password Vault         │")
		fmt.Printf("│  Vault: %-35s│\n", truncate(p.Vault, 35))
		fmt.Println("└────────────────────────────────────────────┘")
		fmt.Println()
		fmt.Println("  1) List entries")
		fmt.Println("  2) Search entries")
		fmt.Println("  3) View / copy entry")
		fmt.Println("  4) Add entry")
		fmt.Println("  5) Manage folders")
		fmt.Println("  6) Backup")
		fmt.Println("  7) Start web UI")
		fmt.Println("  8) Doctor")
		fmt.Println("  9) Change master password")
		fmt.Println("  10) Edit entry")
		fmt.Println("  0) Quit")
		fmt.Println()
		choice, err := readLine("Select [0-9]: ")
		if err != nil && choice == "" {
			return nil
		}
		switch strings.TrimSpace(choice) {
		case "1":
			st.list()
		case "2":
			st.search()
		case "3":
			st.view()
		case "4":
			st.add()
		case "5":
			st.folders()
		case "6":
			st.backups()
		case "7":
			st.serve()
		case "8":
			_ = doctorReport(p, s, false)
		case "9":
			st.passwd()
		case "10":
			st.editEntryPrompt()
		case "0", "q", "quit", "exit":
			return nil
		default:
			fmt.Println("Invalid selection.")
		}
	}
}

func (st *menuState) list() {
	views := st.v.Payload.List()
	if len(views) == 0 {
		fmt.Println("No entries yet.")
		return
	}
	last := ""
	for _, view := range views {
		if view.Folder != last {
			fmt.Printf("\n%s (%d)\n", view.Folder, st.v.Payload.FolderCount(view.Folder))
			last = view.Folder
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
	fmt.Printf("\nTotal: %d entries, %d folders\n", len(views), len(st.v.Payload.Folders))
}

func (st *menuState) search() {
	query, err := promptRequired("Search")
	if err != nil {
		return
	}
	results := st.v.Payload.Search(query, "")
	if len(results) == 0 {
		fmt.Println("No results.")
		return
	}
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
	index, err := promptInt("Select entry to copy [1-"+strconv.Itoa(len(results))+", b=back]", 1)
	if err != nil || index < 1 || index > len(results) {
		return
	}
	selected := results[index-1]
	entry, ok := st.v.Payload.GetEntry(selected.Folder, selected.Name)
	if !ok {
		fmt.Println("Entry not found.")
		return
	}
	st.copyValue(selected.Folder, selected.Name, "password", entry.Password)
}

func (st *menuState) view() {
	views := st.v.Payload.List()
	if len(views) == 0 {
		fmt.Println("No entries yet.")
		return
	}
	for i, view := range views {
		fmt.Printf("  [%d] %s/%s   %s\n", i+1, view.Folder, view.Name, view.Username)
	}
	index, err := promptInt("Select entry [1-"+strconv.Itoa(len(views))+", 0=cancel]", 0)
	if err != nil || index < 1 || index > len(views) {
		return
	}
	selected := views[index-1]
	entry, ok := st.v.Payload.GetEntry(selected.Folder, selected.Name)
	if !ok {
		fmt.Println("Entry not found.")
		return
	}
	fmt.Printf("Entry    : %s/%s\n", selected.Folder, selected.Name)
	fmt.Printf("Username : %s\n", entry.Username)
	fmt.Printf("Password : %s\n", entry.Password)
	if len(entry.Tags) > 0 {
		fmt.Printf("Tags     : %s\n", strings.Join(entry.Tags, ", "))
	}
	if entry.Pinned {
		fmt.Println("Pinned   : yes")
	}
	fmt.Printf("Updated  : %s\n", entry.UpdatedAt)
	yes, _ := confirm("Copy password to clipboard?", false)
	if yes {
		st.copyValue(selected.Folder, selected.Name, "password", entry.Password)
	}
	edit, _ := confirm("Edit this entry?", false)
	if edit {
		st.editEntry(selected.Folder, selected.Name)
	}
}

func (st *menuState) copyValue(folder, name, field, value string) {
	scheduled, err := clipboard.Copy(value, clipboardClearSeconds())
	if err != nil {
		fmt.Println("Clipboard error:", err)
		return
	}
	fmt.Printf("[OK] %s for '%s/%s' copied.\n", field, folder, name)
	if scheduled {
		fmt.Println("[i]  Clipboard will be cleared in 30 seconds.")
	}
}

func (st *menuState) add() {
	path, err := promptRequired("Entry (folder/name)")
	if err != nil {
		return
	}
	folder, name, err := vault.ParsePath(path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if _, exists := st.v.Payload.GetEntry(folder, name); exists {
		fmt.Println("Entry already exists.")
		return
	}
	templateName, _ := promptString("Template (none/server/database/api-token/ssh-key)", "none")
	defaults, ok := entryTemplates[templateName]
	if templateName != "none" && !ok {
		fmt.Println("Unknown template; using none.")
		templateName = "none"
	}
	usernameDefault := ""
	length := 20
	if ok {
		usernameDefault = defaults.Username
		length = defaults.Length
	}
	username, _ := promptString("Username (optional)", usernameDefault)
	tags, _ := promptString("Tags (comma separated)", "")
	pinned, _ := confirm("Pinned/favorite?", false)
	generate, _ := confirm("Generate a random password?", false)
	var password string
	if generate {
		password, err = generatePassword(length)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Printf("[OK] Generated password: %s\n", password)
		fmt.Println("[i]  This is shown only once.")
	} else {
		for {
			password, err = readPassword("Password: ")
			if err != nil {
				return
			}
			if password == "" {
				fmt.Println("Password cannot be empty.")
				continue
			}
			confirmPassword, err := readPassword("Confirm Password: ")
			if err != nil {
				return
			}
			if password != confirmPassword {
				fmt.Println("Passwords do not match. Try again.")
				continue
			}
			break
		}
	}
	entry := vault.Entry{Username: username, Password: password, Tags: splitTags(tags), Pinned: pinned}
	if err := st.v.Payload.AddEntry(folder, name, entry); err != nil {
		fmt.Println("Error:", err)
		return
	}
	res, err := commitVault(st.p, st.s, st.v, "add")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("[OK] Entry '%s/%s' saved.\n", folder, name)
	printBackupResult(res)
}

func (st *menuState) folders() {
	for {
		fmt.Println("\nFolders")
		fmt.Println("  1) List folders")
		fmt.Println("  2) Add folder")
		fmt.Println("  3) Remove folder")
		fmt.Println("  4) Rename folder")
		fmt.Println("  0) Back")
		choice, err := readLine("Select [0-4]: ")
		if err != nil && choice == "" {
			return
		}
		switch strings.TrimSpace(choice) {
		case "1":
			for _, name := range st.v.Payload.FolderNames() {
				fmt.Printf("  %-16s (%d)\n", name, st.v.Payload.FolderCount(name))
			}
		case "2":
			name, err := promptRequired("Folder name")
			if err != nil {
				return
			}
			if _, ok := st.v.Payload.Folders[name]; ok {
				fmt.Println("Folder already exists.")
				continue
			}
			if err := st.v.Payload.EnsureFolder(name); err != nil {
				fmt.Println("Error:", err)
				continue
			}
			res, err := commitVault(st.p, st.s, st.v, "folder-add")
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			fmt.Println("[OK] Folder created.")
			printBackupResult(res)
		case "3":
			name, err := promptRequired("Folder name")
			if err != nil {
				return
			}
			if name == vault.DefaultFolder {
				fmt.Println("The default folder cannot be removed.")
				continue
			}
			count := st.v.Payload.FolderCount(name)
			if count > 0 {
				value, _ := readLine(fmt.Sprintf("Folder has %d entries. Type DELETE to continue: ", count))
				if strings.TrimSpace(value) != "DELETE" {
					fmt.Println("Cancelled.")
					continue
				}
			}
			if err := st.v.Payload.RemoveFolder(name, true); err != nil {
				fmt.Println("Error:", err)
				continue
			}
			res, err := commitVault(st.p, st.s, st.v, "folder-remove")
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			fmt.Println("[OK] Folder deleted.")
			printBackupResult(res)
		case "4":
			oldName, err := promptRequired("Old folder name")
			if err != nil {
				return
			}
			newName, err := promptRequired("New folder name")
			if err != nil {
				return
			}
			if oldName == vault.DefaultFolder {
				fmt.Println("The default folder cannot be renamed.")
				continue
			}
			if _, ok := st.v.Payload.Folders[oldName]; !ok {
				fmt.Println("Folder not found.")
				continue
			}
			if err := st.v.Payload.RenameFolder(oldName, newName); err != nil {
				fmt.Println("Error:", err)
				continue
			}
			res, err := commitVault(st.p, st.s, st.v, "folder-rename")
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			fmt.Printf("[OK] Folder '%s' renamed to '%s'.\n", oldName, newName)
			printBackupResult(res)
		case "0", "b", "back":
			return
		}
	}
}

func (st *menuState) backups() {
	for {
		fmt.Println("\nBackup")
		fmt.Println("  1) Status")
		fmt.Println("  2) Create snapshot")
		fmt.Println("  3) List snapshots")
		fmt.Println("  4) Sync to remote")
		fmt.Println("  5) Prune")
		fmt.Println("  6) Verify all snapshots")
		fmt.Println("  7) Restore latest")
		fmt.Println("  8) Export vault (for new PC)")
		fmt.Println("  9) Restore vault from file")
		fmt.Println("  0) Back")
		choice, err := readLine("Select [0-9]: ")
		if err != nil && choice == "" {
			return
		}
		switch strings.TrimSpace(choice) {
		case "1":
			st.backupStatus()
		case "2":
			res, err := st.bm.Create(st.v.Path, "manual")
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			if res.Path == "" {
				fmt.Println("No new snapshot was needed.")
			} else {
				fmt.Printf("[OK] Snapshot: %s\n", res.Path)
				if res.Warning != "" {
					fmt.Println("[WARN]", res.Warning)
				}
			}
		case "3":
			printBackupList(st.bm)
		case "4":
			n, err := st.bm.Sync()
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Printf("[OK] %d snapshots synced.\n", n)
			}
		case "5":
			if err := st.bm.PruneDir(st.s.Backup.LocalDir); err != nil {
				fmt.Println("Error:", err)
			} else if st.s.HasRemote() {
				if err := st.bm.PruneDir(st.s.Backup.RemoteDir); err != nil {
					fmt.Println("Error:", err)
				}
			}
			fmt.Println("[OK] Retention applied.")
		case "6":
			password, err := promptPassword("Master Password")
			if err != nil {
				return
			}
			results, err := st.bm.VerifyAll(password)
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			for _, r := range results {
				if r.OK {
					fmt.Printf("[OK]   %-42s (%d folders, %d entries)\n", r.Name, r.Folders, r.Entries)
				} else {
					fmt.Printf("[FAIL] %-42s %s\n", r.Name, r.Error)
				}
			}
		case "7":
			password, err := promptPassword("Master Password")
			if err != nil {
				return
			}
			latest, err := st.bm.Latest()
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			value, _ := readLine("This will replace the current vault. Type RESTORE to continue: ")
			if strings.TrimSpace(value) != "RESTORE" {
				fmt.Println("Cancelled.")
				continue
			}
			if err := st.bm.Restore(latest, st.p.Vault, password); err != nil {
				fmt.Println("Error:", err)
				continue
			}
			v, err := vault.Open(st.p.Vault, password)
			if err != nil {
				fmt.Println("Restored, but could not reload vault:", err)
				return
			}
			st.v = v
			st.bm = backup.New(st.p, st.s)
			fmt.Println("[OK] Vault restored.")
		case "8":
			st.exportVault()
		case "9":
			st.restoreVaultFromFile()
		case "0", "b", "back":
			return
		}
	}
}

func (st *menuState) exportVault() {
	dest, err := promptRequired("Destination file")
	if err != nil {
		return
	}
	password, err := promptPassword("Master Password")
	if err != nil {
		return
	}
	exported, err := st.bm.Export(dest, st.v.Path, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("[OK] Exported encrypted vault to %s\n", exported)
	fmt.Println("[i]  Copy this file to the new PC, then use Restore vault from file.")
}

func (st *menuState) restoreVaultFromFile() {
	source, err := promptRequired("Source file")
	if err != nil {
		return
	}
	password, err := promptPassword("Master Password")
	if err != nil {
		return
	}
	result, err := st.bm.Verify(source, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if !result.OK {
		fmt.Printf("[FAIL] Backup cannot be decrypted: %s\n", result.Error)
		return
	}
	fmt.Printf("[OK] Backup verified (%d folders, %d entries)\n", result.Folders, result.Entries)
	value, err := readLine("This will replace the current vault. Type RESTORE to continue: ")
	if err != nil {
		return
	}
	if strings.TrimSpace(value) != "RESTORE" {
		fmt.Println("Cancelled.")
		return
	}
	if err := st.bm.Restore(source, st.p.Vault, password); err != nil {
		fmt.Println("Error:", err)
		return
	}
	v, err := vault.Open(st.p.Vault, password)
	if err != nil {
		fmt.Println("Restored, but could not reload vault:", err)
		return
	}
	st.v = v
	st.bm = backup.New(st.p, st.s)
	fmt.Println("[OK] Vault restored and verified.")
}

func (st *menuState) backupStatus() {
	status := st.bm.Status()
	fmt.Printf("Backup    : %s (enabled=%v)\n", status.Mode, status.Enabled)
	fmt.Printf("Local     : %s (%d snapshots, %s)\n", status.LocalDir, status.LocalCount, humanBytes(status.LocalBytes))
	if st.s.HasRemote() {
		state := "OK"
		if !status.RemoteOK {
			state = "UNAVAILABLE: " + status.RemoteError
		}
		fmt.Printf("Remote    : %s (%d snapshots, %s) [%s]\n", status.RemoteDir, status.RemoteCount, humanBytes(status.RemoteBytes), state)
	}
	fmt.Printf("Retention : %d snapshots / %d MB\n", status.KeepLast, status.MaxTotalMB)
	if status.Latest != "" {
		fmt.Printf("Latest    : %s\n", status.Latest)
	}
}

func (st *menuState) passwd() {
	password, err := newPasswordConfirmed()
	if err != nil {
		return
	}
	if _, err := st.bm.Create(st.v.Path, "pre-passwd"); err != nil {
		fmt.Println("[WARN] Could not create a pre-change snapshot:", err)
	}
	if err := st.v.Rekey(password, crypto.DefaultParams()); err != nil {
		fmt.Println("Error:", err)
		return
	}
	res, err := st.bm.Create(st.v.Path, "passwd")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("[OK] Master Password changed.")
	printBackupResult(res)
}

func (st *menuState) serve() {
	secret, err := config.EnsureSecret(st.p.Secret)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	host := envOr("FVAULT_HOST", "127.0.0.1")
	port := envOr("FVAULT_PORT", "auto")
	err = web.Run(web.Config{
		Host:         host,
		Port:         port,
		Paths:        st.p,
		Settings:     st.s,
		Secret:       secret,
		TemplatesDir: resolveAssetDir("", "FVAULT_TEMPLATES", "templates"),
		StaticDir:    resolveAssetDir("", "FVAULT_STATIC", "static"),
		CookieSecure: envBool("FVAULT_COOKIE_SECURE", false),
		TrustProxy:   envBool("FVAULT_TRUST_PROXY", false),
		SessionTTL:   envDurationMinutes("FVAULT_SESSION_TTL_MINUTES", 30),
		MaxAttempts:  envInt("FVAULT_MAX_ATTEMPTS", 10),
		Lockout:      envDurationMinutes("FVAULT_LOCKOUT_MINUTES", 15),
	})
	if err != nil {
		fmt.Println("Web server error:", err)
	}
}

func printBackupList(bm *backup.Manager) {
	records, err := bm.List()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if len(records) == 0 {
		fmt.Println("No snapshots found.")
		return
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
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return "..." + s[len(s)-(n-3):]
}
