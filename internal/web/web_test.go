package web

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"fvault/internal/config"
	"fvault/internal/crypto"
	"fvault/internal/ratelimit"
	"fvault/internal/recovery"
	"fvault/internal/vault"
)

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func newTestServer(t *testing.T) (*Server, *vault.Vault) {
	t.Helper()
	home := t.TempDir()
	p := config.NewPaths(home)
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := config.EnsureSecret(p.Secret); err != nil {
		t.Fatalf("EnsureSecret: %v", err)
	}
	v, err := vault.Create(p.Vault, "master-password", "alice", crypto.Params{
		Time: 1, MemoryKiB: 8 * 1024, Threads: 1,
	})
	if err != nil {
		t.Fatalf("vault.Create: %v", err)
	}
	settings := config.DefaultSettings(p)
	if err := config.SaveSettings(p, settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	tpl, err := template.New("").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}).ParseGlob(filepath.Join("..", "..", "templates", "*.html"))
	if err != nil {
		t.Fatalf("ParseGlob: %v", err)
	}
	s := &Server{
		cfg: Config{
			Paths:        p,
			Settings:     settings,
			TemplatesDir: filepath.Join("..", "..", "templates"),
			StaticDir:    filepath.Join("..", "..", "static"),
			SessionTTL:   time.Minute,
			MaxAttempts:  3,
			Lockout:      time.Minute,
		},
		templates: tpl,
		sessions:  newSessionStore(time.Minute),
		limiter:   ratelimit.New(3, time.Minute),
	}
	return s, v
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 5 * time.Second}
}

func get(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	return readBody(t, resp)
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

func postForm(t *testing.T, client *http.Client, target string, values url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return resp
}

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	m := csrfRE.FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatalf("CSRF token not found in page: %s", body)
	}
	return m[1]
}

func TestLoginAndEntryFlow(t *testing.T) {
	s, _ := newTestServer(t)
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	client := newClient(t)

	loginPage := get(t, client, ts.URL+"/login")
	csrf := csrfFrom(t, loginPage)

	resp := postForm(t, client, ts.URL+"/login", url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"master-password"},
	})
	vaultPage := readBody(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(vaultPage, "All entries") {
		t.Fatalf("login failed: status=%d body=%s", resp.StatusCode, vaultPage)
	}
	csrf = csrfFrom(t, vaultPage)

	resp = postForm(t, client, ts.URL+"/entry/new", url.Values{
		"csrf":     {csrf},
		"folder":   {"server-1"},
		"name":     {"db"},
		"username": {"root"},
		"password": {"hunter2"},
	})
	entryPage := readBody(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(entryPage, "Reveal") {
		t.Fatalf("entry was not created: status=%d body=%s", resp.StatusCode, entryPage)
	}
	if !strings.Contains(entryPage, "Reveal") {
		t.Fatalf("entry page is missing the reveal button: %s", entryPage)
	}

	csrf = csrfFrom(t, entryPage)
	resp = postForm(t, client, ts.URL+"/entry/value", url.Values{
		"csrf":   {csrf},
		"folder": {"server-1"},
		"name":   {"db"},
		"field":  {"password"},
	})
	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode value response: %v", err)
	}
	resp.Body.Close()
	if payload["value"] != "hunter2" {
		t.Fatalf("value = %q", payload["value"])
	}

	resp = postForm(t, client, ts.URL+"/entry/value", url.Values{
		"csrf":   {"wrong"},
		"folder": {"server-1"},
		"name":   {"db"},
		"field":  {"password"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad CSRF status = %d, want 403", resp.StatusCode)
	}

	resp = postForm(t, client, ts.URL+"/entry/delete", url.Values{
		"csrf":   {csrf},
		"folder": {"server-1"},
		"name":   {"db"},
	})
	afterDelete := readBody(t, resp)
	resp.Body.Close()
	if !strings.Contains(afterDelete, "Entry deleted") {
		t.Fatalf("delete confirmation missing: %s", afterDelete)
	}
}

func TestUnauthenticatedRedirect(t *testing.T) {
	s, _ := newTestServer(t)
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	client := newClient(t)

	body := get(t, client, ts.URL+"/vault")
	if !strings.Contains(body, "Unlock your vault") {
		t.Fatalf("expected login page, got: %s", body)
	}
}

func TestLoginLockout(t *testing.T) {
	s, _ := newTestServer(t)
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	client := newClient(t)

	var last *http.Response
	for i := 0; i < 3; i++ {
		csrf := csrfFrom(t, get(t, client, ts.URL+"/login"))
		last = postForm(t, client, ts.URL+"/login", url.Values{
			"csrf":     {csrf},
			"username": {"alice"},
			"password": {"wrong"},
		})
		last.Body.Close()
	}
	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third failure status = %d, want 429", last.StatusCode)
	}

	csrf := csrfFrom(t, get(t, client, ts.URL+"/login"))
	locked := postForm(t, client, ts.URL+"/login", url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"master-password"},
	})
	defer locked.Body.Close()
	if locked.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("correct password during lockout status = %d, want 429", locked.StatusCode)
	}
	if locked.Header.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

func TestChangePassword(t *testing.T) {
	s, _ := newTestServer(t)
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	client := newClient(t)
	noRedirect := &http.Client{
		Jar:           client.Jar,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	loginPage := get(t, client, ts.URL+"/login")
	csrf := csrfFrom(t, loginPage)
	resp := postForm(t, client, ts.URL+"/login", url.Values{
		"csrf": {csrf}, "username": {"alice"}, "password": {"master-password"},
	})
	body := readBody(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d: %s", resp.StatusCode, body)
	}

	// The change form is reachable from the nav username link.
	formPage := get(t, client, ts.URL+"/settings/password")
	if !strings.Contains(formPage, "Change Master Password") {
		t.Fatalf("form page missing: %s", formPage)
	}
	csrf = csrfFrom(t, formPage)

	// Wrong current password is rejected.
	resp = postForm(t, noRedirect, ts.URL+"/settings/password", url.Values{
		"csrf": {csrf}, "current": {"wrong"}, "new": {"brand-new-master-pass"}, "confirm": {"brand-new-master-pass"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "incorrect") {
		t.Fatalf("wrong current password not rejected: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Mismatched and short passwords are rejected.
	resp = postForm(t, noRedirect, ts.URL+"/settings/password", url.Values{
		"csrf": {csrf}, "current": {"master-password"}, "new": {"aaaaaaaa"}, "confirm": {"bbbbbbbb"},
	})
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "do+not+match") {
		t.Fatalf("mismatch not rejected: %q", resp.Header.Get("Location"))
	}
	resp = postForm(t, noRedirect, ts.URL+"/settings/password", url.Values{
		"csrf": {csrf}, "current": {"master-password"}, "new": {"short"}, "confirm": {"short"},
	})
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "at+least+8") {
		t.Fatalf("short password not rejected: %q", resp.Header.Get("Location"))
	}

	// Success: redirected to the login page with a notice.
	resp = postForm(t, noRedirect, ts.URL+"/settings/password", url.Values{
		"csrf": {csrf}, "current": {"master-password"}, "new": {"brand-new-master-pass"}, "confirm": {"brand-new-master-pass"},
	})
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/login?notice=") {
		t.Fatalf("success redirect = %d %q", resp.StatusCode, loc)
	}

	// All sessions were cleared: the vault page redirects to login again.
	resp, err := noRedirect.Get(ts.URL + "/vault")
	if err != nil {
		t.Fatalf("GET /vault: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("vault after change = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The old password no longer works, the new one does.
	loginPage = get(t, client, ts.URL+"/login")
	csrf = csrfFrom(t, loginPage)
	resp = postForm(t, noRedirect, ts.URL+"/login", url.Values{
		"csrf": {csrf}, "username": {"alice"}, "password": {"master-password"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password status = %d, want 401", resp.StatusCode)
	}
	resp = postForm(t, noRedirect, ts.URL+"/login", url.Values{
		"csrf": {csrf}, "username": {"alice"}, "password": {"brand-new-master-pass"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/vault" {
		t.Fatalf("new password login = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestForgotPassword(t *testing.T) {
	s, v := newTestServer(t)
	questions := []string{recovery.Questions[0], recovery.Questions[1], recovery.Questions[2]}
	answers := []string{"Smith", "Fluffy", "Kuala Lumpur"}
	if err := recovery.Setup(s.cfg.Paths.Recovery, questions, answers, v.Key); err != nil {
		t.Fatalf("recovery.Setup: %v", err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	client := newClient(t)
	noRedirect := &http.Client{
		Jar:           client.Jar,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// The forgot page shows the configured questions.
	page := get(t, client, ts.URL+"/forgot")
	if !strings.Contains(page, "maiden name") || !strings.Contains(page, "first pet") {
		t.Fatalf("questions missing from forgot page: %s", page)
	}
	csrf := csrfFrom(t, page)

	// Wrong answers are rejected and counted.
	resp := postForm(t, noRedirect, ts.URL+"/forgot", url.Values{
		"csrf":    {csrf},
		"answer1": {"Wrong"}, "answer2": {"Wrong"}, "answer3": {"Wrong"},
		"new": {"brand-new-pass-1"}, "confirm": {"brand-new-pass-1"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong answers status = %d, want 401", resp.StatusCode)
	}

	// Correct answers reset the password.
	resp = postForm(t, noRedirect, ts.URL+"/forgot", url.Values{
		"csrf":    {csrf},
		"answer1": {"smith"}, "answer2": {"FLUFFY"}, "answer3": {"kuala   lumpur"},
		"new": {"brand-new-pass-1"}, "confirm": {"brand-new-pass-1"},
	})
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/login?notice=") {
		t.Fatalf("reset redirect = %d %q", resp.StatusCode, loc)
	}

	// Old password fails, new one logs in.
	loginPage := get(t, client, ts.URL+"/login")
	csrf = csrfFrom(t, loginPage)
	resp = postForm(t, noRedirect, ts.URL+"/login", url.Values{
		"csrf": {csrf}, "username": {"alice"}, "password": {"master-password"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password status = %d, want 401", resp.StatusCode)
	}
	resp = postForm(t, noRedirect, ts.URL+"/login", url.Values{
		"csrf": {csrf}, "username": {"alice"}, "password": {"brand-new-pass-1"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/vault" {
		t.Fatalf("new password login = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The questions keep working with the new key (blob re-wrapped).
	if _, err := recovery.OpenVaultKey(s.cfg.Paths.Recovery, answers); err != nil {
		t.Fatalf("recovery after reset: %v", err)
	}
}

func TestBulkOperations(t *testing.T) {
	s, _ := newTestServer(t)
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	client := newClient(t)
	noRedirect := &http.Client{
		Jar:           client.Jar,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	loginPage := get(t, client, ts.URL+"/login")
	csrf := csrfFrom(t, loginPage)
	resp := postForm(t, client, ts.URL+"/login", url.Values{
		"csrf": {csrf}, "username": {"alice"}, "password": {"master-password"},
	})
	body := readBody(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d: %s", resp.StatusCode, body)
	}
	csrf = csrfFrom(t, body)

	for _, name := range []string{"db", "web"} {
		resp = postForm(t, client, ts.URL+"/entry/new", url.Values{
			"csrf": {csrf}, "folder": {"server-1"}, "name": {name},
			"username": {"root"}, "password": {"hunter2-" + name},
		})
		body = readBody(t, resp)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Reveal") {
			t.Fatalf("create %s failed: %d %s", name, resp.StatusCode, body)
		}
	}

	// Bulk move both entries to general.
	resp = postForm(t, noRedirect, ts.URL+"/entries/move", url.Values{
		"csrf": {csrf}, "folder": {"general"}, "names": {"server-1/db,server-1/web"},
	})
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "folder=general") {
		t.Fatalf("bulk move redirect = %d %q", resp.StatusCode, loc)
	}
	page := get(t, client, ts.URL+"/vault?folder=general")
	if !strings.Contains(page, ">db<") || !strings.Contains(page, ">web<") {
		t.Fatalf("entries not in general after move: %s", page)
	}
	page = get(t, client, ts.URL+"/vault?folder=server-1")
	if strings.Contains(page, ">db<") || strings.Contains(page, ">web<") {
		t.Fatalf("entries still in server-1: %s", page)
	}

	// Bulk delete is rejected without a CSRF token.
	resp = postForm(t, noRedirect, ts.URL+"/entries/delete", url.Values{
		"csrf": {"wrong"}, "names": {"general/db"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad csrf status = %d, want 403", resp.StatusCode)
	}

	// Bulk delete removes them.
	resp = postForm(t, noRedirect, ts.URL+"/entries/delete", url.Values{
		"csrf": {csrf}, "names": {"general/db,general/web"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "Deleted+2") {
		t.Fatalf("bulk delete redirect = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	page = get(t, client, ts.URL+"/vault?folder=general")
	if !strings.Contains(page, "No entries yet") {
		t.Fatalf("entries not deleted: %s", page)
	}
}

func TestForgotPasswordWithRecoveryKey(t *testing.T) {
	s, v := newTestServer(t)
	questions := []string{recovery.Questions[0], recovery.Questions[1], recovery.Questions[2]}
	answers := []string{"Smith", "Fluffy", "Kuala Lumpur"}
	if err := recovery.Setup(s.cfg.Paths.Recovery, questions, answers, v.Key); err != nil {
		t.Fatalf("recovery.Setup: %v", err)
	}
	key, err := recovery.SetupKey(s.cfg.Paths.Recovery, v.Key)
	if err != nil {
		t.Fatalf("recovery.SetupKey: %v", err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	client := newClient(t)
	noRedirect := &http.Client{
		Jar:           client.Jar,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// The page offers both credentials.
	page := get(t, client, ts.URL+"/forgot")
	if !strings.Contains(page, "mode=answers") || !strings.Contains(page, "mode=key") {
		t.Fatalf("choice links missing: %s", page)
	}
	// The key mode shows a key input.
	page = get(t, client, ts.URL+"/forgot?mode=key")
	if !strings.Contains(page, `name="recovery_key"`) {
		t.Fatalf("recovery key input missing: %s", page)
	}
	csrf := csrfFrom(t, page)

	// A well-formed but wrong key fails.
	wrongKey := strings.Repeat("0000-", 7) + "0000"
	resp := postForm(t, noRedirect, ts.URL+"/forgot", url.Values{
		"csrf": {csrf}, "mode": {"key"}, "recovery_key": {wrongKey},
		"new": {"brand-new-pass-9"}, "confirm": {"brand-new-pass-9"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong key status = %d, want 401", resp.StatusCode)
	}

	// The real key resets the password.
	resp = postForm(t, noRedirect, ts.URL+"/forgot", url.Values{
		"csrf": {csrf}, "mode": {"key"}, "recovery_key": {key},
		"new": {"brand-new-pass-9"}, "confirm": {"brand-new-pass-9"},
	})
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/login?notice=") {
		t.Fatalf("reset redirect = %d %q", resp.StatusCode, loc)
	}
	if !strings.Contains(loc, "Security+questions+were+cleared") {
		t.Fatalf("missing questions-cleared note in %q", loc)
	}

	// Login with the new password works, the old one does not.
	loginPage := get(t, client, ts.URL+"/login")
	csrf = csrfFrom(t, loginPage)
	resp = postForm(t, noRedirect, ts.URL+"/login", url.Values{
		"csrf": {csrf}, "username": {"alice"}, "password": {"master-password"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password status = %d, want 401", resp.StatusCode)
	}
	resp = postForm(t, noRedirect, ts.URL+"/login", url.Values{
		"csrf": {csrf}, "username": {"alice"}, "password": {"brand-new-pass-9"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("new password login = %d", resp.StatusCode)
	}

	// The key survived its own reset (re-wrapped), the questions did not.
	if _, err := recovery.OpenVaultKeyWithRecoveryKey(s.cfg.Paths.Recovery, key); err != nil {
		t.Fatalf("key after reset: %v", err)
	}
	if _, err := recovery.QuestionsFor(s.cfg.Paths.Recovery); !errors.Is(err, recovery.ErrNotConfigured) {
		t.Fatalf("questions after key reset: %v", err)
	}
}
