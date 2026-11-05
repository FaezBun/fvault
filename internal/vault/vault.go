package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"fvault/internal/config"
	"fvault/internal/crypto"
)

const (
	Version       = 1
	DefaultFolder = "general"
	KDFName       = "argon2id"
	AEADName      = "aes-256-gcm"
)

var (
	ErrExists             = errors.New("entry already exists")
	ErrNotFound           = errors.New("entry not found")
	ErrFolderNotEmpty     = errors.New("folder is not empty")
	ErrDefaultFolder      = errors.New("the default folder cannot be removed")
	ErrInvalidName        = errors.New("invalid name: use letters, numbers, dot, dash or underscore (max 64)")
	ErrInvalidTag         = errors.New("invalid tag: use letters, numbers, dot, dash or underscore (max 32)")
	ErrUnsupportedVersion = errors.New("unsupported vault version")
	nameRE                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Entry struct {
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	URL             string   `json:"url,omitempty"`
	Notes           string   `json:"notes,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Pinned          bool     `json:"pinned,omitempty"`
	PasswordHistory []string `json:"password_history,omitempty"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

type Folder struct {
	Entries map[string]Entry `json:"entries"`
}

type Meta struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
}

type AuditEvent struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Payload struct {
	Version int               `json:"version"`
	Meta    Meta              `json:"meta"`
	Folders map[string]Folder `json:"folders"`
	Audit   []AuditEvent      `json:"audit,omitempty"`
}

type kdfFile struct {
	Name      string `json:"name"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      string `json:"salt"`
}

type aeadFile struct {
	Name  string `json:"name"`
	Nonce string `json:"nonce"`
}

type vaultFile struct {
	Version    int      `json:"version"`
	KDF        kdfFile  `json:"kdf"`
	AEAD       aeadFile `json:"aead"`
	Ciphertext string   `json:"ciphertext"`
}

// Vault is an unlocked vault. Key, Salt and Params are held in memory only.
type Vault struct {
	Path    string
	Payload *Payload
	Key     []byte
	Salt    []byte
	Params  crypto.Params
}

type EntryView struct {
	Folder    string   `json:"folder"`
	Name      string   `json:"name"`
	Username  string   `json:"username"`
	Tags      []string `json:"tags,omitempty"`
	Pinned    bool     `json:"pinned,omitempty"`
	URL       string   `json:"url,omitempty"`
	Notes     string   `json:"notes,omitempty"`
	UpdatedAt string   `json:"updated_at"`
}

type Info struct {
	Version   int
	KDFName   string
	AEADName  string
	Params    crypto.Params
	Salt      []byte
	CreatedAt string
}

var tagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

func fuzzyScore(query, text string) int {
	if query == "" {
		return 0
	}
	qi := 0
	last := -1
	gaps := 0
	for i, r := range text {
		if qi < len(query) && r == rune(query[qi]) {
			if last >= 0 {
				gaps += i - last - 1
			}
			last = i
			qi++
		}
	}
	if qi != len(query) {
		return -1
	}
	if gaps > 100 {
		gaps = 100
	}
	return 100 - gaps
}

func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return ErrInvalidName
	}
	return nil
}

// ParsePath accepts "name" (default folder) or "folder/name".
func ParsePath(path string) (folder, name string, err error) {
	parts := strings.Split(path, "/")
	switch len(parts) {
	case 1:
		folder, name = DefaultFolder, parts[0]
	case 2:
		folder, name = parts[0], parts[1]
	default:
		return "", "", errors.New("entry path must be <name> or <folder>/<name>")
	}
	if err := ValidateName(folder); err != nil {
		return "", "", fmt.Errorf("folder: %w", err)
	}
	if err := ValidateName(name); err != nil {
		return "", "", fmt.Errorf("entry: %w", err)
	}
	return folder, name, nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func NewPayload(username string) *Payload {
	return &Payload{
		Version: Version,
		Meta:    Meta{Username: username, CreatedAt: now()},
		Folders: map[string]Folder{
			DefaultFolder: {Entries: map[string]Entry{}},
		},
	}
}

func buildAAD(version int, kdf kdfFile) []byte {
	return []byte(fmt.Sprintf(
		"fvault|v=%d|kdf=%s|t=%d|m=%d|p=%d|salt=%s|aead=%s",
		version, kdf.Name, kdf.Time, kdf.MemoryKiB, kdf.Threads, kdf.Salt, AEADName,
	))
}

func newKDF(salt []byte, p crypto.Params) kdfFile {
	return kdfFile{
		Name:      KDFName,
		Time:      p.Time,
		MemoryKiB: p.MemoryKiB,
		Threads:   p.Threads,
		Salt:      base64.StdEncoding.EncodeToString(salt),
	}
}

func Create(path, password, username string, params crypto.Params) (*Vault, error) {
	if username == "" {
		return nil, errors.New("username is required")
	}
	salt, err := crypto.RandomBytes(crypto.SaltLen)
	if err != nil {
		return nil, err
	}
	key := crypto.DeriveKey(password, salt, params)
	v := &Vault{
		Path:    path,
		Payload: NewPayload(username),
		Key:     key,
		Salt:    salt,
		Params:  params,
	}
	if err := v.Save(); err != nil {
		return nil, err
	}
	return v, nil
}

func Open(path, password string) (*Vault, error) {
	outer, err := readFile(path)
	if err != nil {
		return nil, err
	}
	if outer.Version != Version {
		return nil, ErrUnsupportedVersion
	}
	if outer.KDF.Name != KDFName || outer.AEAD.Name != AEADName {
		return nil, errors.New("unsupported vault encryption parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(outer.KDF.Salt)
	if err != nil {
		return nil, errors.New("invalid salt in vault")
	}
	params := crypto.Params{
		Time:      outer.KDF.Time,
		MemoryKiB: outer.KDF.MemoryKiB,
		Threads:   outer.KDF.Threads,
	}
	if !params.Valid() {
		return nil, errors.New("invalid KDF parameters in vault")
	}
	key := crypto.DeriveKey(password, salt, params)
	payload, err := decryptWith(outer, key)
	if err != nil {
		return nil, err
	}
	return &Vault{
		Path:    path,
		Payload: payload,
		Key:     key,
		Salt:    salt,
		Params:  params,
	}, nil
}

func OpenWithKey(path string, key, salt []byte, params crypto.Params) (*Vault, error) {
	outer, err := readFile(path)
	if err != nil {
		return nil, err
	}
	if outer.Version != Version {
		return nil, ErrUnsupportedVersion
	}
	outerSalt, err := base64.StdEncoding.DecodeString(outer.KDF.Salt)
	if err != nil {
		return nil, errors.New("invalid salt in vault")
	}
	if string(outerSalt) != string(salt) ||
		outer.KDF.Time != params.Time ||
		outer.KDF.MemoryKiB != params.MemoryKiB ||
		outer.KDF.Threads != params.Threads {
		return nil, errors.New("vault encryption parameters changed; please log in again")
	}
	payload, err := decryptWith(outer, key)
	if err != nil {
		return nil, err
	}
	return &Vault{
		Path:    path,
		Payload: payload,
		Key:     key,
		Salt:    salt,
		Params:  params,
	}, nil
}

func Inspect(path string) (Info, error) {
	outer, err := readFile(path)
	if err != nil {
		return Info{}, err
	}
	salt, err := base64.StdEncoding.DecodeString(outer.KDF.Salt)
	if err != nil {
		return Info{}, errors.New("invalid salt in vault")
	}
	return Info{
		Version:  outer.Version,
		KDFName:  outer.KDF.Name,
		AEADName: outer.AEAD.Name,
		Params: crypto.Params{
			Time:      outer.KDF.Time,
			MemoryKiB: outer.KDF.MemoryKiB,
			Threads:   outer.KDF.Threads,
		},
		Salt: salt,
	}, nil
}

func readFile(path string) (*vaultFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var outer vaultFile
	if err := json.Unmarshal(b, &outer); err != nil {
		return nil, fmt.Errorf("vault is not valid JSON: %w", err)
	}
	return &outer, nil
}

func decryptWith(outer *vaultFile, key []byte) (*Payload, error) {
	nonce, err := base64.StdEncoding.DecodeString(outer.AEAD.Nonce)
	if err != nil {
		return nil, errors.New("invalid nonce in vault")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(outer.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid ciphertext in vault")
	}
	plaintext, err := crypto.Open(key, nonce, ciphertext, buildAAD(outer.Version, outer.KDF))
	if err != nil {
		return nil, err
	}
	var payload Payload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("vault payload is invalid: %w", err)
	}
	if payload.Version != Version {
		return nil, ErrUnsupportedVersion
	}
	if payload.Folders == nil {
		payload.Folders = map[string]Folder{}
	}
	for name, f := range payload.Folders {
		if f.Entries == nil {
			f.Entries = map[string]Entry{}
			payload.Folders[name] = f
		}
	}
	return &payload, nil
}

func (v *Vault) Save() error {
	if v.Payload == nil {
		return errors.New("vault is not loaded")
	}
	if v.Payload.Version == 0 {
		v.Payload.Version = Version
	}
	kdf := newKDF(v.Salt, v.Params)
	plaintext, err := json.Marshal(v.Payload)
	if err != nil {
		return err
	}
	nonce, ciphertext, err := crypto.Seal(v.Key, plaintext, buildAAD(Version, kdf))
	if err != nil {
		return err
	}
	outer := vaultFile{
		Version: Version,
		KDF:     kdf,
		AEAD: aeadFile{
			Name:  AEADName,
			Nonce: base64.StdEncoding.EncodeToString(nonce),
		},
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	b, err := json.MarshalIndent(outer, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := config.WriteAtomic(v.Path, b, 0o600); err != nil {
		return err
	}
	// Verify the round trip before returning so a bug cannot silently destroy
	// the vault.
	if _, err := decryptWith(&outer, v.Key); err != nil {
		return fmt.Errorf("vault verification failed after write: %w", err)
	}
	return nil
}

func (v *Vault) Rekey(newPassword string, params crypto.Params) error {
	salt, err := crypto.RandomBytes(crypto.SaltLen)
	if err != nil {
		return err
	}
	key := crypto.DeriveKey(newPassword, salt, params)
	oldKey, oldSalt, oldParams := v.Key, v.Salt, v.Params
	v.Key, v.Salt, v.Params = key, salt, params
	if err := v.Save(); err != nil {
		v.Key, v.Salt, v.Params = oldKey, oldSalt, oldParams
		return err
	}
	return nil
}

func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if !tagRE.MatchString(tag) {
			continue
		}
		if seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func (p *Payload) recordAudit(action, target, detail string) {
	p.Audit = append(p.Audit, AuditEvent{
		Time:   now(),
		Action: action,
		Target: target,
		Detail: detail,
	})
	if len(p.Audit) > 1000 {
		p.Audit = p.Audit[len(p.Audit)-1000:]
	}
}

func (p *Payload) EnsureFolder(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if p.Folders == nil {
		p.Folders = map[string]Folder{}
	}
	if _, ok := p.Folders[name]; !ok {
		p.Folders[name] = Folder{Entries: map[string]Entry{}}
		p.recordAudit("folder.add", name, "")
	}
	return nil
}

func (p *Payload) FolderNames() []string {
	names := make([]string, 0, len(p.Folders))
	for name := range p.Folders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (p *Payload) FolderCount(name string) int {
	f, ok := p.Folders[name]
	if !ok {
		return 0
	}
	return len(f.Entries)
}

func (p *Payload) AddEntry(folder, name string, entry Entry) error {
	if err := p.EnsureFolder(folder); err != nil {
		return err
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	f := p.Folders[folder]
	if _, exists := f.Entries[name]; exists {
		return ErrExists
	}
	if entry.CreatedAt == "" {
		entry.CreatedAt = now()
	}
	entry.UpdatedAt = now()
	f.Entries[name] = entry
	p.Folders[folder] = f
	return nil
}

func (p *Payload) MoveEntry(oldFolder, newFolder, name string, entry Entry) error {
	if err := ValidateName(newFolder); err != nil {
		return err
	}
	old, ok := p.GetEntry(oldFolder, name)
	if !ok {
		return ErrNotFound
	}
	if oldFolder != newFolder {
		if err := ValidateName(oldFolder); err != nil {
			return err
		}
		if _, exists := p.GetEntry(newFolder, name); exists {
			return ErrExists
		}
		if err := p.EnsureFolder(newFolder); err != nil {
			return err
		}
	}
	if entry.CreatedAt == "" {
		entry.CreatedAt = old.CreatedAt
	}
	if entry.Password != "" && entry.Password != old.Password {
		entry.PasswordHistory = append([]string{old.Password}, entry.PasswordHistory...)
		if len(entry.PasswordHistory) > 5 {
			entry.PasswordHistory = entry.PasswordHistory[:5]
		}
	}
	if entry.Tags == nil {
		entry.Tags = old.Tags
	}
	entry.Tags = normalizeTags(entry.Tags)
	entry.UpdatedAt = now()
	if oldFolder != newFolder {
		oldFolderData := p.Folders[oldFolder]
		delete(oldFolderData.Entries, name)
		p.Folders[oldFolder] = oldFolderData
		newFolderData := p.Folders[newFolder]
		newFolderData.Entries[name] = entry
		p.Folders[newFolder] = newFolderData
		p.recordAudit("entry.move", oldFolder+"/"+name+" -> "+newFolder+"/"+name, "")
	} else {
		f := p.Folders[newFolder]
		f.Entries[name] = entry
		p.Folders[newFolder] = f
		p.recordAudit("entry.update", newFolder+"/"+name, "")
	}
	return nil
}

func (p *Payload) UpdateEntry(folder, name string, entry Entry) error {
	f, ok := p.Folders[folder]
	if !ok {
		return ErrNotFound
	}
	old, ok := f.Entries[name]
	if !ok {
		return ErrNotFound
	}
	if entry.CreatedAt == "" {
		entry.CreatedAt = old.CreatedAt
	}
	if entry.Password != "" && entry.Password != old.Password {
		entry.PasswordHistory = append([]string{old.Password}, entry.PasswordHistory...)
		if len(entry.PasswordHistory) > 5 {
			entry.PasswordHistory = entry.PasswordHistory[:5]
		}
	}
	if entry.Tags == nil {
		entry.Tags = old.Tags
	}
	entry.Tags = normalizeTags(entry.Tags)
	entry.UpdatedAt = now()
	f.Entries[name] = entry
	p.Folders[folder] = f
	p.recordAudit("entry.update", folder+"/"+name, "")
	return nil
}

func (p *Payload) GetEntry(folder, name string) (Entry, bool) {
	f, ok := p.Folders[folder]
	if !ok {
		return Entry{}, false
	}
	e, ok := f.Entries[name]
	return e, ok
}

func (p *Payload) RemoveEntry(folder, name string) error {
	f, ok := p.Folders[folder]
	if !ok {
		return ErrNotFound
	}
	if _, ok := f.Entries[name]; !ok {
		return ErrNotFound
	}
	delete(f.Entries, name)
	p.Folders[folder] = f
	p.recordAudit("entry.remove", folder+"/"+name, "")
	return nil
}

func (p *Payload) RenameFolder(oldName, newName string) error {
	if oldName == DefaultFolder {
		return ErrDefaultFolder
	}
	if err := ValidateName(oldName); err != nil {
		return err
	}
	if err := ValidateName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	folder, ok := p.Folders[oldName]
	if !ok {
		return ErrNotFound
	}
	if _, exists := p.Folders[newName]; exists {
		return ErrExists
	}
	if p.Folders == nil {
		p.Folders = map[string]Folder{}
	}
	p.Folders[newName] = folder
	delete(p.Folders, oldName)
	p.recordAudit("folder.rename", oldName+" -> "+newName, "")
	return nil
}

func (p *Payload) RemoveFolder(name string, force bool) error {
	if name == DefaultFolder {
		return ErrDefaultFolder
	}
	f, ok := p.Folders[name]
	if !ok {
		return errors.New("folder not found")
	}
	if len(f.Entries) > 0 && !force {
		return ErrFolderNotEmpty
	}
	delete(p.Folders, name)
	p.recordAudit("folder.remove", name, "")
	return nil
}

// TagCount pairs a tag with the number of entries that use it.
type TagCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TagCounts returns every tag with its usage count, most used first.
func (p *Payload) TagCounts() []TagCount {
	counts := map[string]int{}
	for _, folder := range p.Folders {
		for _, entry := range folder.Entries {
			for _, tag := range entry.Tags {
				counts[tag]++
			}
		}
	}
	out := make([]TagCount, 0, len(counts))
	for name, count := range counts {
		out = append(out, TagCount{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// eachTagEntry runs fn on every entry carrying the tag and returns how many
// entries were found and changed.
func (p *Payload) eachTagEntry(tag string, fn func(*Entry)) (changed int, found bool) {
	for _, folder := range p.Folders {
		for name, entry := range folder.Entries {
			has := false
			for _, t := range entry.Tags {
				if t == tag {
					has = true
					break
				}
			}
			if !has {
				continue
			}
			found = true
			fn(&entry)
			folder.Entries[name] = entry
			changed++
		}
	}
	return changed, found
}

// RenameTag applies a tag rename to every entry and returns the number of
// entries that changed.
func (p *Payload) RenameTag(oldName, newName string) (int, error) {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if !tagRE.MatchString(oldName) || !tagRE.MatchString(newName) {
		return 0, ErrInvalidTag
	}
	if oldName == newName {
		return 0, nil
	}
	changed, found := p.eachTagEntry(oldName, func(entry *Entry) {
		tags := make([]string, 0, len(entry.Tags))
		for _, tag := range entry.Tags {
			if tag == oldName {
				tag = newName
			}
			dup := false
			for _, existing := range tags {
				if existing == tag {
					dup = true
					break
				}
			}
			if !dup {
				tags = append(tags, tag)
			}
		}
		entry.Tags = normalizeTags(tags)
	})
	if !found {
		return 0, ErrNotFound
	}
	p.recordAudit("tag.rename", oldName+" -> "+newName, fmt.Sprintf("%d entries", changed))
	return changed, nil
}

// DeleteTag removes a tag from every entry and returns the number of entries
// that changed.
func (p *Payload) DeleteTag(name string) (int, error) {
	name = strings.TrimSpace(name)
	if !tagRE.MatchString(name) {
		return 0, ErrInvalidTag
	}
	changed, found := p.eachTagEntry(name, func(entry *Entry) {
		tags := make([]string, 0, len(entry.Tags))
		for _, tag := range entry.Tags {
			if tag != name {
				tags = append(tags, tag)
			}
		}
		entry.Tags = normalizeTags(tags)
	})
	if !found {
		return 0, ErrNotFound
	}
	p.recordAudit("tag.delete", name, fmt.Sprintf("%d entries", changed))
	return changed, nil
}

func (p *Payload) List() []EntryView {
	var out []EntryView
	for folderName, f := range p.Folders {
		for name, e := range f.Entries {
			out = append(out, EntryView{
				Folder:    folderName,
				Name:      name,
				Username:  e.Username,
				Tags:      e.Tags,
				Pinned:    e.Pinned,
				URL:       e.URL,
				Notes:     e.Notes,
				UpdatedAt: e.UpdatedAt,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pinned != out[j].Pinned {
			return out[i].Pinned
		}
		if out[i].Folder == out[j].Folder {
			return out[i].Name < out[j].Name
		}
		return out[i].Folder < out[j].Folder
	})
	return out
}

func (p *Payload) Search(query, folder string) []EntryView {
	q := strings.ToLower(strings.TrimSpace(query))
	type scored struct {
		view  EntryView
		score int
	}
	var out []scored
	for _, v := range p.List() {
		if folder != "" && v.Folder != folder {
			continue
		}
		haystack := strings.ToLower(strings.Join(append([]string{
			v.Folder, v.Name,
		}, v.Tags...), "\x00"))
		score := -1
		if q == "" {
			score = 0
		} else if strings.Contains(haystack, q) {
			score = 1000 - strings.Index(haystack, q)
		} else if fuzzyScore(q, haystack) >= 0 {
			score = fuzzyScore(q, haystack)
		}
		if score >= 0 {
			out = append(out, scored{view: v, score: score})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].view.Pinned != out[j].view.Pinned {
			return out[i].view.Pinned
		}
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		if out[i].view.Folder == out[j].view.Folder {
			return out[i].view.Name < out[j].view.Name
		}
		return out[i].view.Folder < out[j].view.Folder
	})
	result := make([]EntryView, 0, len(out))
	for _, item := range out {
		result = append(result, item.view)
	}
	return result
}

func (p *Payload) RecordAudit(action, target, detail string) {
	p.recordAudit(action, target, detail)
}

func (p *Payload) DuplicateEntries(username, password, folder, name string) []EntryView {
	var out []EntryView
	for _, view := range p.List() {
		if view.Folder == folder && view.Name == name {
			continue
		}
		entry, ok := p.GetEntry(view.Folder, view.Name)
		if !ok {
			continue
		}
		if username != "" && entry.Username == username && entry.Password == password {
			out = append(out, view)
		}
	}
	return out
}

func (p *Payload) TotalEntries() int {
	total := 0
	for _, f := range p.Folders {
		total += len(f.Entries)
	}
	return total
}
