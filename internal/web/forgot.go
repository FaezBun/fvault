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

// handleForgotGet renders the reset page. The user picks one of two
// credentials: the security answers (2 of 3 must be correct) or the recovery
// key. It is public on purpose: this is the page you reach when the Master
// Password is forgotten.
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
	questions, questionsErr := recovery.QuestionsFor(s.cfg.Paths.Recovery)
	hasKey := recovery.HasKey(s.cfg.Paths.Recovery)

	data := s.baseData(sess)
	data.Title = "Forgot Master Password"
	data.RecoveryQuestions = questions
	data.RecoveryHasKey = hasKey

	mode := r.URL.Query().Get("mode")
	if mode != "answers" && mode != "key" {
		if questionsErr == nil {
			mode = "answers"
		} else {
			mode = "key"
		}
	}
	if mode == "answers" && questionsErr != nil {
		mode = "key"
	}
	if mode == "key" && !hasKey {
		mode = "answers"
	}
	data.ForgotMode = mode

	switch {
	case questionsErr != nil && !hasKey:
		data.Error = "Account recovery is not set up for this vault."
	case mode == "answers" && questionsErr != nil:
		data.Error = "Security questions are not configured for this vault."
	case mode == "key" && !hasKey:
		data.Error = "No recovery key is configured for this vault."
	}
	if msg := r.URL.Query().Get("error"); msg != "" {
		data.Error = msg
	}
	if msg := r.URL.Query().Get("notice"); msg != "" {
		data.Notice = msg
	}
	s.render(w, "forgot.html", http.StatusOK, data)
}

// handleForgotPost verifies the chosen credential and re-encrypts the vault
// with a new Master Password.
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
	mode := r.FormValue("mode")
	if mode != "key" {
		mode = "answers"
	}
	if allowed, retry := s.limiter.Allowed(ip); !allowed {
		minutes := int(math.Ceil(retry.Minutes()))
		if minutes < 1 {
			minutes = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(math.Ceil(retry.Seconds()))))
		s.renderForgotError(w, r, sess, mode, fmt.Sprintf("Too many attempts. Try again in %d minutes.", minutes), http.StatusTooManyRequests)
		return
	}

	next := r.FormValue("new")
	confirm := r.FormValue("confirm")
	if next == "" || confirm == "" {
		s.renderForgotError(w, r, sess, mode, "All fields are required.", http.StatusOK)
		return
	}
	if next != confirm {
		s.renderForgotError(w, r, sess, mode, "New passwords do not match.", http.StatusOK)
		return
	}
	if len(next) < 8 {
		s.renderForgotError(w, r, sess, mode, "Master Password must be at least 8 characters.", http.StatusOK)
		return
	}

	var warning, note string
	if mode == "key" {
		warning, note, err = s.resetWithRecoveryKey(r.FormValue("recovery_key"), next)
		if err != nil {
			if errors.Is(err, recovery.ErrNoKey) {
				s.renderForgotError(w, r, sess, mode, "No recovery key is configured for this vault.", http.StatusOK)
				return
			}
			if errors.Is(err, recovery.ErrInvalidKey) {
				s.forgotFailure(w, r, sess, ip, mode, "Recovery key is incorrect.")
				return
			}
			s.renderForgotError(w, r, sess, mode, "Could not reset the Master Password.", http.StatusInternalServerError)
			return
		}
	} else {
		questions, qErr := recovery.QuestionsFor(s.cfg.Paths.Recovery)
		if qErr != nil {
			s.renderForgotError(w, r, sess, mode, "Security questions are not configured for this vault.", http.StatusOK)
			return
		}
		answers := []string{r.FormValue("answer1"), r.FormValue("answer2"), r.FormValue("answer3")}
		warning, note, err = s.resetWithRecovery(answers, next, questions)
		if err != nil {
			if errors.Is(err, recovery.ErrInvalidAnswer) || errors.Is(err, recovery.ErrBadAnswers) {
				s.forgotFailure(w, r, sess, ip, mode, fmt.Sprintf("Answers do not match (%d of %d required).", recovery.AnswerThreshold, len(questions)))
				return
			}
			s.renderForgotError(w, r, sess, mode, "Could not reset the Master Password.", http.StatusInternalServerError)
			return
		}
	}

	s.limiter.Success(ip)
	// Every session held a key for the old password.
	s.sessions.Clear()
	s.clearSessionCookie(w)
	notice := withWarning("Master Password reset. Log in with the new one.", warning)
	if note != "" {
		notice += " " + note
	}
	http.Redirect(w, r, "/login?notice="+urlQuery(notice), http.StatusSeeOther)
}

// resetWithRecovery unlocks the vault with the answers (2-of-3), re-encrypts
// it under newPassword, and re-wraps the answers. A configured recovery key
// cannot be re-wrapped without the key itself, so it is cleared and the
// returned note tells the user about it.
func (s *Server) resetWithRecovery(answers []string, newPassword string, questions []string) (warning, note string, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	info, err := vault.Inspect(s.cfg.Paths.Vault)
	if err != nil {
		return "", "", err
	}
	key, err := recovery.OpenVaultKey(s.cfg.Paths.Recovery, answers)
	if err != nil {
		return "", "", err
	}
	v, err := vault.OpenWithKey(s.cfg.Paths.Vault, key, info.Salt, info.Params)
	if err != nil {
		return "", "", errors.New("the vault could not be opened with these answers")
	}

	settings := s.currentSettings()
	bm := backup.New(s.cfg.Paths, settings)
	if _, err := bm.Create(v.Path, "pre-recovery"); err != nil {
		log.Printf("pre-recovery snapshot: %v", err)
	}
	v.Payload.RecordAudit("vault.rekey", "", "password reset via security questions")
	if err := v.Rekey(newPassword, crypto.DefaultParams()); err != nil {
		return "", "", err
	}
	if err := recovery.Setup(s.cfg.Paths.Recovery, questions, answers, v.Key); err != nil {
		return "", "", err
	}
	if recovery.HasKey(s.cfg.Paths.Recovery) {
		if err := recovery.ClearKey(s.cfg.Paths.Recovery); err != nil {
			return "", "", err
		}
		note = "Recovery key was cleared - create a new one with 'fvault recovery key'."
	}
	res, err := bm.Create(v.Path, "recovery-reset")
	if err != nil {
		return "", "", err
	}
	return res.Warning, note, nil
}

// resetWithRecoveryKey unlocks the vault with the recovery key, re-encrypts
// it under newPassword, and re-wraps the key. The answers cannot be re-wrapped
// without them, so they are cleared and the returned note says so.
func (s *Server) resetWithRecoveryKey(recoveryKey, newPassword string) (warning, note string, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	info, err := vault.Inspect(s.cfg.Paths.Vault)
	if err != nil {
		return "", "", err
	}
	key, err := recovery.OpenVaultKeyWithRecoveryKey(s.cfg.Paths.Recovery, recoveryKey)
	if err != nil {
		return "", "", err
	}
	v, err := vault.OpenWithKey(s.cfg.Paths.Vault, key, info.Salt, info.Params)
	if err != nil {
		return "", "", errors.New("the vault could not be opened with the recovery key")
	}

	settings := s.currentSettings()
	bm := backup.New(s.cfg.Paths, settings)
	if _, err := bm.Create(v.Path, "pre-recovery"); err != nil {
		log.Printf("pre-recovery snapshot: %v", err)
	}
	_, questionsErr := recovery.QuestionsFor(s.cfg.Paths.Recovery)
	v.Payload.RecordAudit("vault.rekey", "", "password reset via recovery key")
	if err := v.Rekey(newPassword, crypto.DefaultParams()); err != nil {
		return "", "", err
	}
	if err := recovery.ClearQuestions(s.cfg.Paths.Recovery); err != nil {
		return "", "", err
	}
	if err := recovery.RewrapKey(s.cfg.Paths.Recovery, recoveryKey, v.Key); err != nil {
		return "", "", err
	}
	if questionsErr == nil {
		note = "Security questions were cleared - run 'fvault recovery setup' again to reconfigure."
	}
	res, err := bm.Create(v.Path, "recovery-reset")
	if err != nil {
		return "", "", err
	}
	return res.Warning, note, nil
}

// renderForgotError re-renders the forgot page with a message.
func (s *Server) renderForgotError(w http.ResponseWriter, r *http.Request, sess *session, mode, message string, status int) {
	data := s.baseData(sess)
	data.Title = "Forgot Master Password"
	data.Error = message
	data.ForgotMode = mode
	data.RecoveryHasKey = recovery.HasKey(s.cfg.Paths.Recovery)
	if questions, err := recovery.QuestionsFor(s.cfg.Paths.Recovery); err == nil {
		data.RecoveryQuestions = questions
	}
	s.render(w, "forgot.html", status, data)
}

// forgotFailure counts a wrong-credential attempt against the shared limiter.
func (s *Server) forgotFailure(w http.ResponseWriter, r *http.Request, sess *session, ip, mode, message string) {
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
	s.renderForgotError(w, r, sess, mode, message, status)
}
