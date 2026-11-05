package cli

import (
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"fvault/internal/clipboard"
	"fvault/internal/config"
	"fvault/internal/web"
)

func newServeCmd() *cobra.Command {
	var host, port string
	var cookieSecure, trustProxy bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the web UI",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			if err := p.Ensure(); err != nil {
				return err
			}
			secret, err := config.EnsureSecret(p.Secret)
			if err != nil {
				return err
			}
			s, err := loadSettings(p)
			if err != nil {
				return err
			}
			if host == "" {
				host = envOr("FVAULT_HOST", "127.0.0.1")
			}
			if port == "" {
				port = envOr("FVAULT_PORT", "auto")
			}
			if !cmd.Flags().Changed("cookie-secure") {
				cookieSecure = envBool("FVAULT_COOKIE_SECURE", false)
			}
			if !cmd.Flags().Changed("trust-proxy") {
				trustProxy = envBool("FVAULT_TRUST_PROXY", false)
			}
			return web.Run(web.Config{
				Host:         host,
				Port:         port,
				Paths:        p,
				Settings:     s,
				Secret:       secret,
				TemplatesDir: resolveAssetDir(templatesFlag, "FVAULT_TEMPLATES", "templates"),
				StaticDir:    resolveAssetDir(staticFlag, "FVAULT_STATIC", "static"),
				CookieSecure: cookieSecure,
				TrustProxy:   trustProxy,
				SessionTTL:   envDurationMinutes("FVAULT_SESSION_TTL_MINUTES", 30),
				MaxAttempts:  envInt("FVAULT_MAX_ATTEMPTS", 10),
				Lockout:      envDurationMinutes("FVAULT_LOCKOUT_MINUTES", 15),
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "listen host (default 127.0.0.1)")
	cmd.Flags().StringVar(&port, "port", "", "listen port: auto, 0, or a number (default auto)")
	cmd.Flags().BoolVar(&cookieSecure, "cookie-secure", false, "mark the session cookie Secure (use with HTTPS)")
	cmd.Flags().BoolVar(&trustProxy, "trust-proxy", false, "trust X-Forwarded-For from a reverse proxy")
	cmd.Flags().StringVar(&templatesFlag, "templates", "", "templates directory (default ./templates)")
	cmd.Flags().StringVar(&staticFlag, "static", "", "static directory (default ./static)")
	return cmd
}

func newClipboardClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "__clipboard-clear <hash> <seconds>",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			seconds, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			return clipboard.ClearIfMatches(args[0], time.Duration(seconds)*time.Second)
		},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func envDurationMinutes(key string, fallback int) time.Duration {
	return time.Duration(envInt(key, fallback)) * time.Minute
}
