// Package recovery implements account recovery through security questions and
// an optional recovery key.
//
// The credentials never decrypt the vault directly. At setup time the vault's
// current encryption key is wrapped with AES-256-GCM under keys derived from
// the answers (Argon2id) and, optionally, from a random recovery key. The
// wrapped blobs live outside the vault in recovery.json, which is why a
// forgotten Master Password can be reset while the vault itself stays
// encrypted the whole time.
//
// Each answer wraps the vault key separately and only AnswerThreshold of the
// three must be correct (2-of-3). One correct answer is never enough.
package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
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
	// AnswerThreshold is how many of the three answers must be correct.
	AnswerThreshold = 2
	// KeyLength is the number of hex characters in a recovery key
	// (128 bits, displayed as eight hyphen-separated groups).
	KeyLength = 32
)

var (
	ErrNotConfigured = errors.New("security questions are not configured")
	ErrInvalidAnswer = errors.New("answers do not match")
	ErrBadQuestions  = errors.New("pick three distinct questions from the list")
	ErrBadAnswers    = fmt.Errorf("answers must be at least %d characters", MinAnswerLen)
	ErrNoKey         = errors.New("recovery key is not configured")
	ErrInvalidKey    = errors.New("recovery key is invalid or incorrect")
)

// answerBlob is one AES-256-GCM wrapping of the vault key.
type answerBlob struct {
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	Wrapped string `json:"wrapped"`
}

type file struct {
	Version   int      `json:"version"`
	CreatedAt string   `json:"created_at"`
	Questions []string `json:"questions,omitempty"`
	// Legacy single blob: all three answers joined (written by early builds).
	Salt    string `json:"salt,omitempty"`
	Nonce   string `json:"nonce,omitempty"`
	Wrapped string `json:"wrapped,omitempty"`
	// Per-answer blobs: any AnswerThreshold of them unwrap the vault key.
	Answers []answerBlob `json:"answers,omitempty"`
	// Optional recovery key: a second credential wrapping the vault key.
	KeySalt  string        `json:"key_salt,omitempty"`
	KeyNonce string        `json:"key_nonce,omitempty"`
	KeyWrap  string        `json:"key_wrapped,omitempty"`
	Params   crypto.Params `json:"params"`
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

// aadAnswer binds a blob to the question set and its position.
func aadAnswer(questions []string, index int) []byte {
	return []byte(fmt.Sprintf("fvault-recovery\x00%s\x00%d", strings.Join(questions, "\x00"), index))
}

// aadLegacy binds the pre-threshold single blob (all answers joined).
func aadLegacy(questions []string) []byte {
	return []byte("fvault-recovery\x00" + strings.Join(questions, "\x00"))
}

// aadKey binds the recovery-key blob.
func aadKey() []byte {
	return []byte("fvault-recovery-key")
}

// seal wraps vaultKey under password with a fresh salt and nonce.
func seal(password string, vaultKey []byte, aadBytes []byte) (answerBlob, error) {
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return answerBlob{}, err
	}
	kek := crypto.DeriveKey(password, salt, crypto.DefaultParams())
	block, err := aes.NewCipher(kek)
	if err != nil {
		return answerBlob{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return answerBlob{}, err
	}
	nonce, err := crypto.RandomBytes(gcm.NonceSize())
	if err != nil {
		return answerBlob{}, err
	}
	wrapped := gcm.Seal(nil, nonce, vaultKey, aadBytes)
	return answerBlob{
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Wrapped: base64.StdEncoding.EncodeToString(wrapped),
	}, nil
}

// open unwraps a blob; the error is returned verbatim so callers can map it.
func open(blob answerBlob, password string, aadBytes []byte, params crypto.Params) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(blob.Salt)
	if err != nil {
		return nil, errors.New("recovery file is corrupt")
	}
	nonce, err := base64.StdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return nil, errors.New("recovery file is corrupt")
	}
	wrapped, err := base64.StdEncoding.DecodeString(blob.Wrapped)
	if err != nil {
		return nil, errors.New("recovery file is corrupt")
	}
	kek := crypto.DeriveKey(password, salt, params)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, wrapped, aadBytes)
}

func write(path string, data *file) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// Setup wraps vaultKey under each of the three answers (2-of-3 threshold)
// and writes the recovery file with 0600 permissions. An existing recovery
// key is preserved.
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
	blobs := make([]answerBlob, 0, len(answers))
	for i, a := range answers {
		blob, err := seal(NormalizeAnswer(a), vaultKey, aadAnswer(questions, i))
		if err != nil {
			return err
		}
		blobs = append(blobs, blob)
	}
	data := &file{
		Version:   Version,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Questions: questions,
		Answers:   blobs,
		Params:    crypto.DefaultParams(),
	}
	// Keep the recovery key credential if one is already configured.
	if existing, err := Load(path); err == nil && existing.KeyWrap != "" {
		data.KeySalt, data.KeyNonce, data.KeyWrap = existing.KeySalt, existing.KeyNonce, existing.KeyWrap
	}
	return write(path, data)
}

// Load reads the recovery file. Returns ErrNotConfigured when no file exists.
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
	if data.Version != Version {
		return nil, errors.New("unsupported recovery file")
	}
	if len(data.Answers) > 0 && len(data.Answers) != 3 {
		return nil, errors.New("unsupported recovery file")
	}
	if len(data.Answers) == 0 && data.Wrapped == "" && data.KeyWrap == "" {
		return nil, errors.New("unsupported recovery file")
	}
	return &data, nil
}

// QuestionsFor returns the configured questions, or ErrNotConfigured when the
// file is missing or holds no questions.
func QuestionsFor(path string) ([]string, error) {
	data, err := Load(path)
	if err != nil {
		return nil, err
	}
	if len(data.Questions) != 3 {
		return nil, ErrNotConfigured
	}
	return data.Questions, nil
}

// OpenVaultKey unwraps the stored vault key. AnswerThreshold (2) of the three
// answers must be correct; a single correct answer is not enough.
func OpenVaultKey(path string, answers []string) ([]byte, error) {
	data, err := Load(path)
	if err != nil {
		return nil, err
	}
	if len(data.Questions) != 3 {
		return nil, ErrNotConfigured
	}
	if err := validateAnswers(answers); err != nil {
		return nil, err
	}
	if len(data.Answers) == 3 {
		correct := 0
		var key []byte
		for i, a := range answers {
			k, err := open(data.Answers[i], NormalizeAnswer(a), aadAnswer(data.Questions, i), data.Params)
			if err == nil {
				correct++
				key = k
			}
		}
		if correct < AnswerThreshold {
			return nil, ErrInvalidAnswer
		}
		return key, nil
	}
	// Legacy single blob: all three answers are required.
	key, err := open(answerBlob{Salt: data.Salt, Nonce: data.Nonce, Wrapped: data.Wrapped},
		joinAnswers(answers), aadLegacy(data.Questions), data.Params)
	if err != nil {
		return nil, ErrInvalidAnswer
	}
	return key, nil
}

// GenerateRecoveryKey returns a fresh 128-bit key grouped for readability.
func GenerateRecoveryKey() (string, error) {
	raw, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return FormatRecoveryKey(hex.EncodeToString(raw)), nil
}

// FormatRecoveryKey groups a 32-character key as xxxx-xxxx-....
func FormatRecoveryKey(key string) string {
	var groups []string
	for len(key) > 4 {
		groups = append(groups, key[:4])
		key = key[4:]
	}
	if len(key) > 0 {
		groups = append(groups, key)
	}
	return strings.Join(groups, "-")
}

// NormalizeRecoveryKey lower-cases and strips separators so the key matches
// no matter how it is pasted.
func NormalizeRecoveryKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.NewReplacer("-", "", " ", "", "\t", "").Replace(key)
	return key
}

// SetupKey wraps vaultKey under a freshly generated recovery key and returns
// the key to save offline. Existing questions are preserved.
func SetupKey(path string, vaultKey []byte) (string, error) {
	if len(vaultKey) == 0 {
		return "", errors.New("empty vault key")
	}
	key, err := GenerateRecoveryKey()
	if err != nil {
		return "", err
	}
	blob, err := seal(NormalizeRecoveryKey(key), vaultKey, aadKey())
	if err != nil {
		return "", err
	}
	data := &file{
		Version:   Version,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		KeySalt:   blob.Salt,
		KeyNonce:  blob.Nonce,
		KeyWrap:   blob.Wrapped,
		Params:    crypto.DefaultParams(),
	}
	if existing, err := Load(path); err == nil {
		data.Questions, data.Answers = existing.Questions, existing.Answers
		data.Salt, data.Nonce, data.Wrapped = existing.Salt, existing.Nonce, existing.Wrapped
		data.Params = existing.Params
	}
	return key, write(path, data)
}

// RewrapKey re-wraps an existing recovery key under a new vault key (used
// after a reset that was done with the key itself).
func RewrapKey(path, key string, vaultKey []byte) error {
	data, err := Load(path)
	if err != nil {
		return err
	}
	if data.KeyWrap == "" {
		return ErrNoKey
	}
	blob, err := seal(NormalizeRecoveryKey(key), vaultKey, aadKey())
	if err != nil {
		return err
	}
	data.KeySalt, data.KeyNonce, data.KeyWrap = blob.Salt, blob.Nonce, blob.Wrapped
	return write(path, data)
}

// HasKey reports whether a recovery key is configured.
func HasKey(path string) bool {
	data, err := Load(path)
	return err == nil && data.KeyWrap != ""
}

// OpenVaultKeyWithRecoveryKey unwraps the vault key with the recovery key.
func OpenVaultKeyWithRecoveryKey(path, key string) ([]byte, error) {
	data, err := Load(path)
	if err != nil {
		return nil, err
	}
	if data.KeyWrap == "" {
		return nil, ErrNoKey
	}
	normalized := NormalizeRecoveryKey(key)
	if len(normalized) != KeyLength {
		return nil, ErrInvalidKey
	}
	vaultKey, err := open(answerBlob{Salt: data.KeySalt, Nonce: data.KeyNonce, Wrapped: data.KeyWrap},
		normalized, aadKey(), data.Params)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return vaultKey, nil
}

// ClearKey removes only the recovery-key credential.
func ClearKey(path string) error {
	data, err := Load(path)
	if err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return nil
		}
		return err
	}
	if data.KeyWrap == "" {
		return nil
	}
	data.KeySalt, data.KeyNonce, data.KeyWrap = "", "", ""
	return dropIfEmpty(path, data)
}

// ClearQuestions removes only the security-question credential.
func ClearQuestions(path string) error {
	data, err := Load(path)
	if err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return nil
		}
		return err
	}
	if len(data.Questions) == 0 && data.Wrapped == "" {
		return nil
	}
	data.Questions = nil
	data.Salt, data.Nonce, data.Wrapped = "", "", ""
	data.Answers = nil
	return dropIfEmpty(path, data)
}

func dropIfEmpty(path string, data *file) error {
	if data.KeyWrap == "" && len(data.Answers) == 0 && data.Wrapped == "" {
		return Remove(path)
	}
	return write(path, data)
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
