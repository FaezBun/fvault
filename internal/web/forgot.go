package web

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"

	"fvault/internal/backup"
	"fvault/internal/crypto"
	"fvault/internal/recovery"
	"fvault/internal/vault"
)

// handleForgotGet renders the security-question reset form. It is public on
// purpose: this is the page you reach when the Master Password is forgotten.
func (s *Server) handleForgotGet(w http.ResponseWriter, r *http.Request) {
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
	data.Title = "Forgot Master Password"
	questions, err := recovery.QuestionsFor(s.cfg.Paths.Recovery)
	if err != nil {
		data.Error = "Account recovery is not set up for this vault."
	} else {
		data.RecoveryQuestions = questions
	}
	if msg := r.URL.Query().Get("error"); msg != "" {
		data.Error = msg
	}
	if msg := r.URL.Query().Get("notice"); msg != "" {
		data.Notice = msg
	}
	s.render(w, "forgot.html", http.StatusOK, data)
}

// handleForgotPost verifies the three answers and re-encrypts the vault with
// a new Master Password.
func (s *Server) handleForgotPost(w http.ResponseWriter, r *http.Request) {
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
		s.renderForgotError(w, r, sess, fmt.Sprintf("Too many attempts. Try again in %d minutes.", minutes), http.StatusTooManyRequests)
		return
	}

	questions, err := recovery.QuestionsFor(s.cfg.Paths.Recovery)
	if err != nil {
		s.renderForgotError(w, r, sess, "Account recovery is not set up for this vault.", http.StatusOK)
		return
	}
	answers := []string{r.FormValue("answer1"), r.FormValue("answer2"), r.FormValue("answer3")}
	next := r.FormValue("new")
	confirm := r.FormValue("confirm")
	if next == "" || confirm == "" {
		s.renderForgotError(w, r, sess, "All fields are required.", http.StatusOK)
		return
	}
	if next != confirm {
		s.renderForgotError(w, r, sess, "New passwords do not match.", http.StatusOK)
		return
	}
	if len(next) < 8 {
		s.renderForgotError(w, r, sess, "Master Password must be at least 8 characters.", http.StatusOK)
		return
	}

	warning, err := s.resetWithRecovery(answers, next, questions)
	if err != nil {
		if errors.Is(err, recovery.ErrInvalidAnswer) || errors.Is(err, recovery.ErrBadAnswers) {
			s.forgotFailure(w, r, sess, ip, "Answers do not match.")
			return
		}
		s.renderForgotError(w, r, sess, "Could not reset the Master Password.", http.StatusInternalServerError)
		return
	}
	s.limiter.Success(ip)
	// Every session held a key for the old password.
	s.sessions.Clear()
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login?notice="+urlQuery(withWarning("Master Password reset. Log in with the new one.", warning)),
		http.StatusSeeOther)
}

// resetWithRecovery unlocks the vault with the answers, re-encrypts it under
// newPassword, and re-wraps the recovery blob so the questions stay valid.
func (s *Server) resetWithRecovery(answers []string, newPassword string, questions []string) (string, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	info, err := vault.Inspect(s.cfg.Paths.Vault)
	if err != nil {
		return "", err
	}
	key, err := recovery.OpenVaultKey(s.cfg.Paths.Recovery, answers)
	if err != nil {
		return "", err
	}
	v, err := vault.OpenWithKey(s.cfg.Paths.Vault, key, info.Salt, info.Params)
	if err != nil {
		return "", errors.New("the vault could not be opened with these answers")
	}

	settings := s.currentSettings()
	bm := backup.New(s.cfg.Paths, settings)
	if _, err := bm.Create(v.Path, "pre-recovery"); err != nil {
		log.Printf("pre-recovery snapshot: %v", err)
	}
	v.Payload.RecordAudit("vault.rekey", "", "password reset via security questions")
	if err := v.Rekey(newPassword, crypto.DefaultParams()); err != nil {
		return "", err
	}
	if err := recovery.Setup(s.cfg.Paths.Recovery, questions, answers, v.Key); err != nil {
		return "", err
	}
	res, err := bm.Create(v.Path, "recovery-reset")
	if err != nil {
		return "", err
	}
	return res.Warning, nil
}

// renderForgotError re-renders the forgot page with a message.
func (s *Server) renderForgotError(w http.ResponseWriter, r *http.Request, sess *session, message string, status int) {
	data := s.baseData(sess)
	data.Title = "Forgot Master Password"
	data.Error = message
	if questions, err := recovery.QuestionsFor(s.cfg.Paths.Recovery); err == nil {
		data.RecoveryQuestions = questions
	}
	s.render(w, "forgot.html", status, data)
}

// forgotFailure counts a wrong-answer attempt against the shared limiter.
func (s *Server) forgotFailure(w http.ResponseWriter, r *http.Request, sess *session, ip, message string) {
	locked, retry := s.limiter.Failure(ip)
	status := http.StatusUnauthorized
	if locked {
		minutes := int(math.Ceil(retry.Minutes()))
		if minutes < 1 {
			minutes = 1
		}
		message = fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", minutes)
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(math.Ceil(retry.Seconds()))))
	}
	s.renderForgotError(w, r, sess, message, status)
}
