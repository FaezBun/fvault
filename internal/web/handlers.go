package web

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"fvault/internal/backup"
	"fvault/internal/vault"
)

type folderView struct {
	Name   string
	Count  int
	Active bool
}

type entryFormData struct {
	Folder    string
	OldFolder string
	Name      string
	Username  string
	Tags      string
	Pinned    bool
	IsEdit    bool
}

type backupPageData struct {
	Enabled      bool
	Mode         string
	LocalDir     string
	RemoteDir    string
	Latest       string
	LocalCount   int
	RemoteCount  int
	LocalBytes   string
	RemoteBytes  string
	RemoteOK     bool
	RemoteError  string
	KeepLast     int
	MaxTotalMB   int
	RemoteMarker string
	Records      []backup.Record
}

type pageData struct {
	Title             string
	LoggedIn          bool
	Username          string
	CSRF              string
	Notice            string
	Error             string
	Query             string
	Folder            string
	Tag               string
	Sort              string
	RecoveryQuestions []string
	Folders           []folderView
	Entries           []vault.EntryView
	Tags              []vault.TagCount
	Entry             entryFormData
	Backup            backupPageData
}

func (s *Server) baseData(sess *session) pageData {
	data := pageData{}
	if sess != nil {
		data.LoggedIn = sess.Authenticated
		data.Username = sess.Username
		data.CSRF = sess.CSRF
	}
	return data
}

func (s *Server) render(w http.ResponseWriter, name string, status int, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		logTemplateError(name, err)
	}
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, message string) {
	sess := s.sessionFromRequest(r)
	data := s.baseData(sess)
	data.Title = "Error"
	data.Error = message
	s.render(w, "error.html", status, data)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if sess != nil && sess.Authenticated {
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	sess, err := s.ensureSession(w, r)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not create a session.")
		return
	}
	if sess.Authenticated {
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}
	data := s.baseData(sess)
	data.Title = "Login"
	data.Notice = r.URL.Query().Get("notice")
	data.Error = r.URL.Query().Get("error")
	s.render(w, "login.html", http.StatusOK, data)
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	sess, err := s.ensureSession(w, r)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not create a session.")
		return
	}
	if !s.requireCSRF(w, r, sess) {
		return
	}
	ip := s.clientIP(r)
	if allowed, retry := s.limiter.Allowed(ip); !allowed {
		minutes := int(math.Ceil(retry.Minutes()))
		if minutes < 1 {
			minutes = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(math.Ceil(retry.Seconds()))))
		data := s.baseData(sess)
		data.Title = "Login"
		data.Error = fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", minutes)
		s.render(w, "login.html", http.StatusTooManyRequests, data)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		s.loginFailure(w, r, sess, ip, "Invalid username or password.", http.StatusUnauthorized)
		return
	}
	v, err := vault.Open(s.cfg.Paths.Vault, password)
	if err != nil {
		s.loginFailure(w, r, sess, ip, "Invalid username or password.", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(v.Payload.Meta.Username), []byte(username)) != 1 {
		s.loginFailure(w, r, sess, ip, "Invalid username or password.", http.StatusUnauthorized)
		return
	}
	s.limiter.Success(ip)
	s.sessions.Upgrade(sess, v.Key, v.Salt, v.Params, v.Payload.Meta.Username)
	s.setSessionCookie(w, sess)
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

func (s *Server) loginFailure(w http.ResponseWriter, r *http.Request, sess *session, ip, message string, status int) {
	locked, retry := s.limiter.Failure(ip)
	if locked {
		minutes := int(math.Ceil(retry.Minutes()))
		if minutes < 1 {
			minutes = 1
		}
		message = fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", minutes)
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(math.Ceil(retry.Seconds()))))
	}
	data := s.baseData(sess)
	data.Title = "Login"
	data.Error = message
	s.render(w, "login.html", status, data)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if sess != nil {
		if err := r.ParseForm(); err == nil && csrfValid(r, sess) {
			s.sessions.Delete(sess.ID)
		}
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleVault(w http.ResponseWriter, r *http.Request, sess *session) {
	v, err := s.loadVault(sess)
	if err != nil {
		s.invalidateAndLogin(w, r, sess, "Your session has expired. Please log in again.")
		return
	}
	query := r.URL.Query()
	folder := query.Get("folder")
	if folder != "" {
		if err := vault.ValidateName(folder); err != nil {
			s.renderError(w, r, http.StatusBadRequest, "Invalid folder name.")
			return
		}
	}
	q := query.Get("q")
	tag := strings.TrimSpace(query.Get("tag"))
	sortMode := query.Get("sort")
	if sortMode != "tags" {
		sortMode = ""
	}

	data := s.baseData(sess)
	data.Title = "Vault"
	data.Notice = query.Get("notice")
	data.Error = query.Get("error")
	data.Query = q
	data.Folder = folder
	data.Tag = tag
	data.Sort = sortMode
	for _, name := range v.Payload.FolderNames() {
		data.Folders = append(data.Folders, folderView{
			Name:   name,
			Count:  v.Payload.FolderCount(name),
			Active: name == folder,
		})
	}
	data.Tags = v.Payload.TagCounts()
	switch {
	case q != "":
		data.Entries = v.Payload.Search(q, folder)
	case folder != "":
		data.Entries = v.Payload.Search("", folder)
	default:
		data.Entries = v.Payload.List()
	}
	if tag != "" {
		filtered := data.Entries[:0]
		for _, entry := range data.Entries {
			if hasTag(entry.Tags, tag) {
				filtered = append(filtered, entry)
			}
		}
		data.Entries = filtered
	}
	if sortMode == "tags" {
		sort.SliceStable(data.Entries, func(i, j int) bool {
			left := ""
			if len(data.Entries[i].Tags) > 0 {
				left = strings.Join(data.Entries[i].Tags, ",")
			}
			right := ""
			if len(data.Entries[j].Tags) > 0 {
				right = strings.Join(data.Entries[j].Tags, ",")
			}
			if left != right {
				return left < right
			}
			if data.Entries[i].Folder == data.Entries[j].Folder {
				return data.Entries[i].Name < data.Entries[j].Name
			}
			return data.Entries[i].Folder < data.Entries[j].Folder
		})
	}
	if sortMode == "updated" {
		sort.SliceStable(data.Entries, func(i, j int) bool {
			if data.Entries[i].UpdatedAt != data.Entries[j].UpdatedAt {
				return data.Entries[i].UpdatedAt > data.Entries[j].UpdatedAt
			}
			if data.Entries[i].Folder == data.Entries[j].Folder {
				return data.Entries[i].Name < data.Entries[j].Name
			}
			return data.Entries[i].Folder < data.Entries[j].Folder
		})
	}
	s.render(w, "vault.html", http.StatusOK, data)
}

func (s *Server) handleEntryView(w http.ResponseWriter, r *http.Request, sess *session) {
	folder := r.URL.Query().Get("folder")
	name := r.URL.Query().Get("name")
	if vault.ValidateName(folder) != nil || vault.ValidateName(name) != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid entry name.")
		return
	}
	v, err := s.loadVault(sess)
	if err != nil {
		s.invalidateAndLogin(w, r, sess, "Your session has expired. Please log in again.")
		return
	}
	entry, ok := v.Payload.GetEntry(folder, name)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Entry not found.")
		return
	}
	data := s.baseData(sess)
	data.Title = name
	data.Notice = r.URL.Query().Get("notice")
	data.Error = r.URL.Query().Get("error")
	data.Entry = entryFormData{
		Folder:   folder,
		Name:     name,
		Username: entry.Username,
		Tags:     strings.Join(entry.Tags, ", "),
		Pinned:   entry.Pinned,
	}
	s.render(w, "entry_view.html", http.StatusOK, data)
}

func (s *Server) handleEntryNew(w http.ResponseWriter, r *http.Request, sess *session) {
	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = vault.DefaultFolder
	}
	if vault.ValidateName(folder) != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid folder name.")
		return
	}
	data := s.baseData(sess)
	data.Title = "New entry"
	data.Entry = entryFormData{Folder: folder}
	v, err := s.loadVault(sess)
	if err == nil {
		for _, name := range v.Payload.FolderNames() {
			data.Folders = append(data.Folders, folderView{Name: name})
		}
	}
	s.render(w, "entry_form.html", http.StatusOK, data)
}

func (s *Server) handleEntryCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireCSRF(w, r, sess) {
		return
	}
	folder := strings.TrimSpace(r.FormValue("folder"))
	name := strings.TrimSpace(r.FormValue("name"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	tags := strings.TrimSpace(r.FormValue("tags"))
	pinned := r.FormValue("pinned") == "1" || r.FormValue("pinned") == "on"
	data := s.baseData(sess)
	data.Title = "New entry"
	data.Entry = entryFormData{Folder: folder, Name: name, Username: username, Tags: tags, Pinned: pinned}
	if err := vault.ValidateName(folder); err != nil {
		data.Error = "Invalid folder name."
		s.render(w, "entry_form.html", http.StatusBadRequest, data)
		return
	}
	if err := vault.ValidateName(name); err != nil {
		data.Error = "Invalid entry name."
		s.render(w, "entry_form.html", http.StatusBadRequest, data)
		return
	}
	if password == "" {
		data.Error = "Password is required."
		s.render(w, "entry_form.html", http.StatusBadRequest, data)
		return
	}
	tagList := splitTagsWeb(tags)
	entry := vault.Entry{Username: username, Password: password, Tags: tagList, Pinned: pinned}
	duplicateWarning := ""
	if v, err := s.loadVault(sess); err == nil {
		dups := v.Payload.DuplicateEntries(username, password, folder, name)
		if len(dups) > 0 {
			names := make([]string, 0, len(dups))
			for _, dup := range dups {
				names = append(names, dup.Folder+"/"+dup.Name)
			}
			duplicateWarning = "a similar entry already exists: " + strings.Join(names, ", ")
		}
	}
	warning, err := s.writeVault(sess, "add", func(p *vault.Payload) error {
		return p.AddEntry(folder, name, entry)
	})
	if err != nil {
		if errors.Is(err, vault.ErrExists) {
			data.Error = "An entry with that name already exists."
			s.render(w, "entry_form.html", http.StatusBadRequest, data)
			return
		}
		s.handleWriteError(w, r, sess, err)
		return
	}
	redirectWith(w, r, "/entry", map[string]string{
		"folder": folder,
		"name":   name,
		"notice": withWarning("Entry created.", combineWarnings(warning, duplicateWarning)),
	})
}

func (s *Server) handleEntryEdit(w http.ResponseWriter, r *http.Request, sess *session) {
	folder := r.URL.Query().Get("folder")
	name := r.URL.Query().Get("name")
	if vault.ValidateName(folder) != nil || vault.ValidateName(name) != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid entry name.")
		return
	}
	v, err := s.loadVault(sess)
	if err != nil {
		s.invalidateAndLogin(w, r, sess, "Your session has expired. Please log in again.")
		return
	}
	entry, ok := v.Payload.GetEntry(folder, name)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Entry not found.")
		return
	}
	data := s.baseData(sess)
	data.Title = "Edit " + name
	data.Entry = entryFormData{
		Folder:    folder,
		OldFolder: folder,
		Name:      name,
		Username:  entry.Username,
		Tags:      strings.Join(entry.Tags, ", "),
		Pinned:    entry.Pinned,
		IsEdit:    true,
	}
	v2, err := s.loadVault(sess)
	if err == nil {
		for _, folderName := range v2.Payload.FolderNames() {
			data.Folders = append(data.Folders, folderView{Name: folderName})
		}
	}
	s.render(w, "entry_form.html", http.StatusOK, data)
}

func (s *Server) handleEntryUpdate(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireCSRF(w, r, sess) {
		return
	}
	folder := strings.TrimSpace(r.FormValue("folder"))
	oldFolder := strings.TrimSpace(r.FormValue("old_folder"))
	if oldFolder == "" {
		oldFolder = folder
	}
	name := strings.TrimSpace(r.FormValue("name"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	tags := strings.TrimSpace(r.FormValue("tags"))
	pinned := r.FormValue("pinned") == "1" || r.FormValue("pinned") == "on"
	data := s.baseData(sess)
	data.Title = "Edit " + name
	data.Entry = entryFormData{Folder: folder, OldFolder: oldFolder, Name: name, Username: username, Tags: tags, Pinned: pinned, IsEdit: true}
	if vault.ValidateName(oldFolder) != nil || vault.ValidateName(folder) != nil || vault.ValidateName(name) != nil {
		data.Error = "Invalid entry name."
		s.render(w, "entry_form.html", http.StatusBadRequest, data)
		return
	}
	warning, err := s.writeVault(sess, "update", func(p *vault.Payload) error {
		old, ok := p.GetEntry(oldFolder, name)
		if !ok {
			return vault.ErrNotFound
		}
		if password == "" {
			password = old.Password
		}
		return p.MoveEntry(oldFolder, folder, name, vault.Entry{
			Username: username,
			Password: password,
			Tags:     splitTagsWeb(tags),
			Pinned:   pinned,
		})
	})
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, "Entry not found.")
			return
		}
		s.handleWriteError(w, r, sess, err)
		return
	}
	redirectWith(w, r, "/entry", map[string]string{
		"folder": folder,
		"name":   name,
		"notice": withWarning("Entry updated.", warning),
	})
}

func (s *Server) handleEntryDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireCSRF(w, r, sess) {
		return
	}
	folder := strings.TrimSpace(r.FormValue("folder"))
	name := strings.TrimSpace(r.FormValue("name"))
	if vault.ValidateName(folder) != nil || vault.ValidateName(name) != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid entry name.")
		return
	}
	warning, err := s.writeVault(sess, "delete", func(p *vault.Payload) error {
		return p.RemoveEntry(folder, name)
	})
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, "Entry not found.")
			return
		}
		s.handleWriteError(w, r, sess, err)
		return
	}
	redirectWith(w, r, "/vault", map[string]string{
		"folder": folder,
		"notice": withWarning("Entry deleted.", warning),
	})
}

func (s *Server) handleEntryValue(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireCSRF(w, r, sess) {
		return
	}
	folder := strings.TrimSpace(r.FormValue("folder"))
	name := strings.TrimSpace(r.FormValue("name"))
	field := r.FormValue("field")
	if vault.ValidateName(folder) != nil || vault.ValidateName(name) != nil {
		http.Error(w, "Invalid entry name", http.StatusBadRequest)
		return
	}
	v, err := s.loadVault(sess)
	if err != nil {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}
	entry, ok := v.Payload.GetEntry(folder, name)
	if !ok {
		http.Error(w, "Entry not found", http.StatusNotFound)
		return
	}
	var value string
	switch field {
	case "password", "":
		value = entry.Password
	case "username":
		value = entry.Username
	default:
		http.Error(w, "Invalid field", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
}

func (s *Server) handleFolderCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireCSRF(w, r, sess) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if err := vault.ValidateName(name); err != nil {
		redirectWith(w, r, "/vault", map[string]string{"error": "Invalid folder name."})
		return
	}
	warning, err := s.writeVault(sess, "folder-add", func(p *vault.Payload) error {
		if _, ok := p.Folders[name]; ok {
			return errors.New("folder already exists")
		}
		return p.EnsureFolder(name)
	})
	if err != nil {
		redirectWith(w, r, "/vault", map[string]string{"error": err.Error()})
		return
	}
	redirectWith(w, r, "/vault", map[string]string{
		"folder": name,
		"notice": withWarning("Folder created.", warning),
	})
}

func (s *Server) handleFolderRename(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireCSRF(w, r, sess) {
		return
	}
	oldName := strings.TrimSpace(r.FormValue("old"))
	newName := strings.TrimSpace(r.FormValue("name"))
	if oldName == vault.DefaultFolder {
		redirectWith(w, r, "/vault", map[string]string{"error": "The default folder cannot be renamed."})
		return
	}
	if vault.ValidateName(oldName) != nil || vault.ValidateName(newName) != nil {
		redirectWith(w, r, "/vault", map[string]string{"error": "Invalid folder name."})
		return
	}
	warning, err := s.writeVault(sess, "folder-rename", func(p *vault.Payload) error {
		return p.RenameFolder(oldName, newName)
	})
	if err != nil {
		redirectWith(w, r, "/vault", map[string]string{"error": err.Error()})
		return
	}
	redirectWith(w, r, "/vault", map[string]string{
		"folder": newName,
		"notice": withWarning("Folder renamed.", warning),
	})
}

// handleTags renders the tag management page.
func (s *Server) handleTags(w http.ResponseWriter, r *http.Request, sess *session) {
	v, err := s.loadVault(sess)
	if err != nil {
		s.invalidateAndLogin(w, r, sess, "Your session has expired. Please log in again.")
		return
	}
	data := s.baseData(sess)
	data.Title = "Tags"
	data.Notice = r.URL.Query().Get("notice")
	data.Error = r.URL.Query().Get("error")
	data.Tags = v.Payload.TagCounts()
	s.render(w, "tags.html", http.StatusOK, data)
}

// tagErrorMessage maps tag errors to a friendly flash message.
func tagErrorMessage(err error) string {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		return "Tag not found."
	case errors.Is(err, vault.ErrInvalidTag):
		return "Invalid tag name. Use letters, numbers, dot, dash or underscore (max 32)."
	default:
		return "Could not update tags."
	}
}

// handleTagRename renames a tag on every entry.
func (s *Server) handleTagRename(w http.ResponseWriter, r *http.Request, sess *session) {
	oldName := strings.TrimSpace(r.FormValue("old"))
	newName := strings.TrimSpace(r.FormValue("name"))
	if oldName == "" || newName == "" {
		redirectWith(w, r, "/tags", map[string]string{"error": "Both tag names are required."})
		return
	}
	warning, err := s.writeVault(sess, "tag-rename", func(p *vault.Payload) error {
		_, err := p.RenameTag(oldName, newName)
		return err
	})
	if err != nil {
		redirectWith(w, r, "/tags", map[string]string{"error": tagErrorMessage(err)})
		return
	}
	redirectWith(w, r, "/tags", map[string]string{
		"notice": withWarning("Tag renamed.", warning),
	})
}

// handleTagDelete removes a tag from every entry.
func (s *Server) handleTagDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWith(w, r, "/tags", map[string]string{"error": "Tag name is required."})
		return
	}
	warning, err := s.writeVault(sess, "tag-delete", func(p *vault.Payload) error {
		_, err := p.DeleteTag(name)
		return err
	})
	if err != nil {
		redirectWith(w, r, "/tags", map[string]string{"error": tagErrorMessage(err)})
		return
	}
	redirectWith(w, r, "/tags", map[string]string{
		"notice": withWarning("Tag removed from every entry.", warning),
	})
}

func (s *Server) handleFolderDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireCSRF(w, r, sess) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	force := r.FormValue("force") == "1"
	if name == vault.DefaultFolder {
		redirectWith(w, r, "/vault", map[string]string{"error": "The default folder cannot be deleted."})
		return
	}
	if err := vault.ValidateName(name); err != nil {
		redirectWith(w, r, "/vault", map[string]string{"error": "Invalid folder name."})
		return
	}
	warning, err := s.writeVault(sess, "folder-delete", func(p *vault.Payload) error {
		if p.FolderCount(name) > 0 && !force {
			return vault.ErrFolderNotEmpty
		}
		return p.RemoveFolder(name, true)
	})
	if err != nil {
		redirectWith(w, r, "/vault", map[string]string{"error": err.Error()})
		return
	}
	redirectWith(w, r, "/vault", map[string]string{"notice": withWarning("Folder deleted.", warning)})
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request, sess *session) {
	data := s.baseData(sess)
	data.Title = "Backups"
	settings := s.currentSettings()
	bm := backup.New(s.cfg.Paths, settings)
	st := bm.Status()
	data.Backup = backupPageData{
		Enabled:      st.Enabled,
		Mode:         st.Mode,
		LocalDir:     st.LocalDir,
		RemoteDir:    st.RemoteDir,
		Latest:       st.Latest,
		LocalCount:   st.LocalCount,
		RemoteCount:  st.RemoteCount,
		LocalBytes:   formatBytes(st.LocalBytes),
		RemoteBytes:  formatBytes(st.RemoteBytes),
		RemoteOK:     st.RemoteOK,
		RemoteError:  st.RemoteError,
		KeepLast:     st.KeepLast,
		MaxTotalMB:   st.MaxTotalMB,
		RemoteMarker: st.RemoteMarker,
	}
	records, err := bm.List()
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Backup.Records = records
	}
	s.render(w, "backup.html", http.StatusOK, data)
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireCSRF(w, r, sess) {
		return
	}
	password := r.FormValue("password")
	if password == "" {
		redirectWith(w, r, "/backup", map[string]string{"error": "Master Password is required."})
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := vault.Open(s.cfg.Paths.Vault, password); err != nil {
		redirectWith(w, r, "/backup", map[string]string{"error": "Invalid Master Password."})
		return
	}
	data, err := os.ReadFile(s.cfg.Paths.Vault)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not read the vault.")
		return
	}
	filename := "fvault-export-" + time.Now().UTC().Format("20060102-150405") + ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if _, err := w.Write(data); err != nil {
		logTemplateError("backup export", err)
	}
}

func hasTag(tags []string, target string) bool {
	for _, tag := range tags {
		if tag == target {
			return true
		}
	}
	return false
}

func (s *Server) handleWriteError(w http.ResponseWriter, r *http.Request, sess *session, err error) {
	if strings.Contains(err.Error(), "parameters changed") {
		s.invalidateAndLogin(w, r, sess, "The vault was re-encrypted. Please log in again.")
		return
	}
	s.renderError(w, r, http.StatusInternalServerError, "Could not save the vault: "+err.Error())
}

func redirectWith(w http.ResponseWriter, r *http.Request, path string, values map[string]string) {
	q := url.Values{}
	for k, v := range values {
		if v != "" {
			q.Set(k, v)
		}
	}
	target := path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func withWarning(notice, warning string) string {
	if warning == "" {
		return notice
	}
	return notice + " Warning: " + warning
}

func urlQuery(s string) string {
	return url.QueryEscape(s)
}

func formatBytes(n int64) string {
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

func combineWarnings(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}

func splitTagsWeb(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}
