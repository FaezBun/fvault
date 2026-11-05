package web

import (
	"encoding/json"
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
	tpl, err := template.ParseGlob(filepath.Join("..", "..", "templates", "*.html"))
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
