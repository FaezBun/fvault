// Package recovery implements account recovery through security questions.
//
// The answers never decrypt the vault directly. At setup time the vault's
// current encryption key is wrapped with AES-256-GCM under a key derived from
// the answers (Argon2id). The wrapped blob lives outside the vault in
// recovery.json, which is why a forgotten Master Password can be reset while
// the vault itself stays encrypted the whole time.
package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"fvault/internal/crypto"
)

// Questions is the fixed list users pick three from, in order.
var Questions = []string{
	"What is your mother's maiden name?",
	"What was the name of your first pet?",
	"In what city were you born?",
	"What was the make and model of your first car?",
	"What was the name of the street you grew up on?",
	"What high school did you attend?",
	"What is your oldest sibling's middle name?",
	"In what town did your parents meet?",
	"What was the name of your favorite stuffed animal as a child?",
	"What was the first movie you ever saw in a theater?",
	"Who was your favorite teacher in elementary school?",
	"What is your absolute least favorite food?",
	"If you could meet one historical figure, who would it be?",
	"What was the first concert you ever attended?",
	"What is the name of the first video game you ever beat?",
	"What was your favorite childhood Halloween costume?",
}

const (
	// MinAnswerLen is the shortest accepted answer.
	MinAnswerLen = 4
	// Version is the recovery file format version.
	Version = 1
)

var (
	ErrNotConfigured = errors.New("security questions are not configured")
	ErrInvalidAnswer = errors.New("answers do not match")
	ErrBadQuestions  = errors.New("pick three distinct questions from the list")
	ErrBadAnswers    = fmt.Errorf("answers must be at least %d characters", MinAnswerLen)
)

type file struct {
	Version   int           `json:"version"`
	CreatedAt string        `json:"created_at"`
	Questions []string      `json:"questions"`
	Salt      string        `json:"salt"`
	Nonce     string        `json:"nonce"`
	Wrapped   string        `json:"wrapped"`
	Params    crypto.Params `json:"params"`
}

// NormalizeAnswer lower-cases, trims, and collapses whitespace so the same
// answer matches no matter how it is typed.
func NormalizeAnswer(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

func joinAnswers(answers []string) string {
	parts := make([]string, len(answers))
	for i, a := range answers {
		parts[i] = NormalizeAnswer(a)
	}
	return strings.Join(parts, "\x00")
}

// ValidateQuestions checks that exactly three distinct questions from the
// fixed list were chosen.
func ValidateQuestions(questions []string) error {
	if len(questions) != 3 {
		return ErrBadQuestions
	}
	seen := map[string]bool{}
	for _, q := range questions {
		found := false
		for _, known := range Questions {
			if q == known {
				found = true
				break
			}
		}
		if !found || seen[q] {
			return ErrBadQuestions
		}
		seen[q] = true
	}
	return nil
}

func validateAnswers(answers []string) error {
	if len(answers) != 3 {
		return ErrBadAnswers
	}
	for _, a := range answers {
		if len(NormalizeAnswer(a)) < MinAnswerLen {
			return ErrBadAnswers
		}
	}
	return nil
}

func aad(questions []string) []byte {
	return []byte("fvault-recovery\x00" + strings.Join(questions, "\x00"))
}

// Setup wraps vaultKey under the answers and writes the recovery file with
// 0600 permissions. It replaces any previous file.
func Setup(path string, questions, answers []string, vaultKey []byte) error {
	if err := ValidateQuestions(questions); err != nil {
		return err
	}
	if err := validateAnswers(answers); err != nil {
		return err
	}
	if len(vaultKey) == 0 {
		return errors.New("empty vault key")
	}
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	params := crypto.DefaultParams()
	kek := crypto.DeriveKey(joinAnswers(answers), salt, params)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce, err := crypto.RandomBytes(gcm.NonceSize())
	if err != nil {
		return err
	}
	wrapped := gcm.Seal(nil, nonce, vaultKey, aad(questions))

	data := file{
		Version:   Version,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Questions: questions,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Wrapped:   base64.StdEncoding.EncodeToString(wrapped),
		Params:    params,
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// Load reads the recovery file and returns its questions. Returns
// ErrNotConfigured when no file exists.
func Load(path string) (*file, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotConfigured
		}
		return nil, err
	}
	var data file
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, errors.New("recovery file is corrupt")
	}
	if data.Version != Version || len(data.Questions) != 3 {
		return nil, errors.New("unsupported recovery file")
	}
	return &data, nil
}

// QuestionsFor returns the configured questions, or ErrNotConfigured.
func QuestionsFor(path string) ([]string, error) {
	data, err := Load(path)
	if err != nil {
		return nil, err
	}
	return data.Questions, nil
}

// OpenVaultKey unwraps the stored vault key using the three answers.
func OpenVaultKey(path string, answers []string) ([]byte, error) {
	data, err := Load(path)
	if err != nil {
		return nil, err
	}
	if err := validateAnswers(answers); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(data.Salt)
	if err != nil {
		return nil, errors.New("recovery file is corrupt")
	}
	nonce, err := base64.StdEncoding.DecodeString(data.Nonce)
	if err != nil {
		return nil, errors.New("recovery file is corrupt")
	}
	wrapped, err := base64.StdEncoding.DecodeString(data.Wrapped)
	if err != nil {
		return nil, errors.New("recovery file is corrupt")
	}
	kek := crypto.DeriveKey(joinAnswers(answers), salt, data.Params)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	key, err := gcm.Open(nil, nonce, wrapped, aad(data.Questions))
	if err != nil {
		return nil, ErrInvalidAnswer
	}
	return key, nil
}

// Remove deletes the recovery file if it exists.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Configured reports whether a recovery file exists.
func Configured(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
