package web

import (
	"log"
	"net/http"

	"fvault/internal/backup"
	"fvault/internal/crypto"
	"fvault/internal/recovery"
	"fvault/internal/vault"
)

// handlePasswordGet renders the change Master Password form.
func (s *Server) handlePasswordGet(w http.ResponseWriter, r *http.Request, sess *session) {
	data := s.baseData(sess)
	data.Title = "Change Master Password"
	data.Notice = r.URL.Query().Get("notice")
	data.Error = r.URL.Query().Get("error")
	s.render(w, "password.html", http.StatusOK, data)
}

// handlePasswordPost verifies the current password, re-encrypts the vault
// with the new one, and logs every session out.
func (s *Server) handlePasswordPost(w http.ResponseWriter, r *http.Request, sess *session) {
	current := r.FormValue("current")
	next := r.FormValue("new")
	confirm := r.FormValue("confirm")

	if current == "" || next == "" || confirm == "" {
		redirectWith(w, r, "/settings/password", map[string]string{"error": "All fields are required."})
		return
	}
	if next != confirm {
		redirectWith(w, r, "/settings/password", map[string]string{"error": "New passwords do not match."})
		return
	}
	if len(next) < 8 {
		redirectWith(w, r, "/settings/password", map[string]string{"error": "Master Password must be at least 8 characters."})
		return
	}
	// Verify the current password against the on-disk vault before touching
	// anything.
	if _, err := vault.Open(s.cfg.Paths.Vault, current); err != nil {
		redirectWith(w, r, "/settings/password", map[string]string{"error": "Current Master Password is incorrect."})
		return
	}

	warning, err := s.writeVaultFull(sess, "passwd", func(v *vault.Vault) error {
		// Best-effort snapshot before re-encrypting.
		bm := backup.New(s.cfg.Paths, s.currentSettings())
		if _, err := bm.Create(v.Path, "pre-passwd"); err != nil {
			log.Printf("pre-passwd snapshot: %v", err)
		}
		if err := v.Rekey(next, crypto.DefaultParams()); err != nil {
			return err
		}
		v.Payload.RecordAudit("vault.rekey", "", "master password changed")
		return nil
	})
	if err != nil {
		redirectWith(w, r, "/settings/password", map[string]string{"error": "Could not change the Master Password."})
		return
	}

	// Every session (including this one) still holds the old vault key.
	s.sessions.Clear()
	s.clearSessionCookie(w)
	notice := withWarning("Master Password changed. Log in again.", warning)
	if recovery.Configured(s.cfg.Paths.Recovery) {
		if err := recovery.Remove(s.cfg.Paths.Recovery); err == nil {
			notice += " Security questions were cleared - run 'fvault recovery setup' again."
		}
	}
	http.Redirect(w, r, "/login?notice="+urlQuery(notice),
		http.StatusSeeOther)
}
