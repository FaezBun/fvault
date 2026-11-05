package web

import (
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fvault/internal/backup"
	"fvault/internal/config"
	"fvault/internal/ratelimit"
	"fvault/internal/vault"
)

type Config struct {
	Host         string
	Port         string
	Paths        config.Paths
	Settings     config.Settings
	Secret       []byte
	TemplatesDir string
	StaticDir    string
	CookieSecure bool
	TrustProxy   bool
	SessionTTL   time.Duration
	MaxAttempts  int
	Lockout      time.Duration
}

type Server struct {
	cfg       Config
	templates *template.Template
	sessions  *sessionStore
	limiter   *ratelimit.Limiter
	writeMu   sync.Mutex
}

func Run(cfg Config) error {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 30 * time.Minute
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.Lockout <= 0 {
		cfg.Lockout = 15 * time.Minute
	}
	if cfg.TemplatesDir == "" {
		cfg.TemplatesDir = "templates"
	}
	if cfg.StaticDir == "" {
		cfg.StaticDir = "static"
	}

	tpl, err := template.New("").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}).ParseGlob(filepath.Join(cfg.TemplatesDir, "*.html"))
	if err != nil {
		return fmt.Errorf("could not load templates from %s: %w", cfg.TemplatesDir, err)
	}
	required := []string{"login.html", "vault.html", "entry_view.html", "entry_form.html", "backup.html", "error.html"}
	for _, name := range required {
		if tpl.Lookup(name) == nil {
			return fmt.Errorf("missing template %s in %s", name, cfg.TemplatesDir)
		}
	}
	if info, err := os.Stat(cfg.StaticDir); err != nil || !info.IsDir() {
		return fmt.Errorf("static directory %s is missing", cfg.StaticDir)
	}

	s := &Server{
		cfg:       cfg,
		templates: tpl,
		sessions:  newSessionStore(cfg.SessionTTL),
		limiter:   ratelimit.New(cfg.MaxAttempts, cfg.Lockout),
	}

	ln, err := listen(cfg.Host, cfg.Port)
	if err != nil {
		return err
	}
	addr, _ := ln.Addr().(*net.TCPAddr)
	port := 0
	if addr != nil {
		port = addr.Port
	}
	displayHost := cfg.Host
	if displayHost == "" || displayHost == "0.0.0.0" || displayHost == "::" {
		displayHost = "127.0.0.1"
	}
	urlHost := net.JoinHostPort(displayHost, strconv.Itoa(port))
	if strings.Contains(displayHost, ":") {
		urlHost = "[" + displayHost + "]:" + strconv.Itoa(port)
	}

	fmt.Printf("[i] Templates : %s\n", cfg.TemplatesDir)
	fmt.Printf("[i] Data      : %s\n", cfg.Paths.Home)
	fmt.Printf("[i] Listening : %s\n", ln.Addr().String())
	fmt.Printf("[i] Web UI    : http://%s\n", urlHost)
	fmt.Println("[i] Login     : username + Master Password")
	fmt.Printf("[i] Rate limit: %d failed attempts -> %s lockout\n", cfg.MaxAttempts, cfg.Lockout)
	if cfg.Host != "" && cfg.Host != "127.0.0.1" && cfg.Host != "localhost" && cfg.Host != "::1" {
		fmt.Println("[WARN] Listening on a non-loopback address. Use HTTPS and a reverse proxy.")
	}

	mux := s.routes()
	handler := s.securityHeaders(mux)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.cleanupLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case <-sigCh:
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		fmt.Println("\n[i] Server stopped.")
		return nil
	}
}

func listen(host, port string) (net.Listener, error) {
	if host == "" {
		host = "127.0.0.1"
	}
	switch strings.ToLower(strings.TrimSpace(port)) {
	case "", "auto":
		var lastErr error
		for p := 8000; p <= 8099; p++ {
			ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
			if err == nil {
				return ln, nil
			}
			lastErr = err
		}
		if ln, err := net.Listen("tcp", net.JoinHostPort(host, "0")); err == nil {
			return ln, nil
		}
		return nil, fmt.Errorf("no free port found: %v", lastErr)
	case "0":
		return net.Listen("tcp", net.JoinHostPort(host, "0"))
	default:
		if _, err := strconv.Atoi(port); err != nil {
			return nil, fmt.Errorf("invalid port %q", port)
		}
		return net.Listen("tcp", net.JoinHostPort(host, port))
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("GET /forgot", s.handleForgotGet)
	mux.HandleFunc("POST /forgot", s.handleForgotPost)
	mux.HandleFunc("POST /logout", s.handleLogout)

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /vault", s.auth(s.handleVault))
	mux.HandleFunc("GET /entry", s.auth(s.handleEntryView))
	mux.HandleFunc("GET /entry/new", s.auth(s.handleEntryNew))
	mux.HandleFunc("POST /entry/new", s.auth(s.handleEntryCreate))
	mux.HandleFunc("GET /entry/edit", s.auth(s.handleEntryEdit))
	mux.HandleFunc("POST /entry/edit", s.auth(s.handleEntryUpdate))
	mux.HandleFunc("POST /entry/delete", s.auth(s.handleEntryDelete))
	mux.HandleFunc("POST /entry/value", s.auth(s.handleEntryValue))
	mux.HandleFunc("POST /folder/new", s.auth(s.handleFolderCreate))
	mux.HandleFunc("POST /folder/delete", s.auth(s.handleFolderDelete))
	mux.HandleFunc("POST /folder/rename", s.auth(s.handleFolderRename))
	mux.HandleFunc("GET /tags", s.auth(s.handleTags))
	mux.HandleFunc("POST /tag/rename", s.auth(s.handleTagRename))
	mux.HandleFunc("POST /tag/delete", s.auth(s.handleTagDelete))
	mux.HandleFunc("GET /backup", s.auth(s.handleBackup))
	mux.HandleFunc("POST /backup/export", s.auth(s.handleBackupExport))
	mux.HandleFunc("GET /settings/password", s.auth(s.handlePasswordGet))
	mux.HandleFunc("POST /settings/password", s.auth(s.handlePasswordPost))

	static := http.FileServer(http.Dir(s.cfg.StaticDir))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		static.ServeHTTP(w, r)
	})))
	return mux
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if s.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sessions.Cleanup()
			s.limiter.Cleanup()
		}
	}
}

func (s *Server) sessionFromRequest(r *http.Request) *session {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	return s.sessions.Get(cookie.Value)
}

func (s *Server) ensureSession(w http.ResponseWriter, r *http.Request) (*session, error) {
	if sess := s.sessionFromRequest(r); sess != nil {
		return sess, nil
	}
	sess, err := s.sessions.Create(false)
	if err != nil {
		return nil, err
	}
	s.setSessionCookie(w, sess)
	return sess, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, sess *session) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   int(s.sessions.ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.cfg.CookieSecure,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.cfg.CookieSecure,
	})
}

type authedHandler func(http.ResponseWriter, *http.Request, *session)

func (s *Server) auth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFromRequest(r)
		if sess == nil || !sess.Authenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s.setSessionCookie(w, sess)
		next(w, r, sess)
	}
}

func csrfValid(r *http.Request, sess *session) bool {
	token := r.FormValue("csrf")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" || sess == nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRF)) == 1
}

func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request, sess *session) bool {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return false
	}
	if !csrfValid(r, sess) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) loadVault(sess *session) (*vault.Vault, error) {
	return vault.OpenWithKey(s.cfg.Paths.Vault, sess.Key, sess.Salt, sess.Params)
}

func (s *Server) currentSettings() config.Settings {
	settings, err := config.LoadSettings(s.cfg.Paths)
	if err != nil {
		return s.cfg.Settings
	}
	return settings
}

func (s *Server) writeVault(sess *session, reason string, fn func(*vault.Payload) error) (string, error) {
	return s.writeVaultFull(sess, reason, func(v *vault.Vault) error {
		return fn(v.Payload)
	})
}

// writeVaultFull serialises a vault mutation that needs the *vault.Vault
// itself (for example Rekey), then saves and takes a snapshot.
func (s *Server) writeVaultFull(sess *session, reason string, fn func(*vault.Vault) error) (string, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	v, err := s.loadVault(sess)
	if err != nil {
		return "", err
	}
	if err := fn(v); err != nil {
		return "", err
	}
	if err := v.Save(); err != nil {
		return "", err
	}
	settings := s.currentSettings()
	res, err := backup.New(s.cfg.Paths, settings).Create(v.Path, reason)
	if err != nil {
		return "", err
	}
	return res.Warning, nil
}

func (s *Server) invalidateAndLogin(w http.ResponseWriter, r *http.Request, sess *session, message string) {
	if sess != nil {
		s.sessions.Delete(sess.ID)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login?error="+urlQuery(message), http.StatusSeeOther)
}

func logTemplateError(name string, err error) {
	if err != nil {
		log.Printf("template %s: %v", name, err)
	}
}
