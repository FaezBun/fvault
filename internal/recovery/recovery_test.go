package recovery

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testQA() (questions, answers []string) {
	return []string{
		Questions[0],
		Questions[1],
		Questions[2],
	}, []string{
		"Smith",
		"Fluffy",
		"Kuala Lumpur",
	}
}

func TestSetupAndOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	questions, answers := testQA()
	key := []byte("0123456789abcdef0123456789abcdef")

	if err := Setup(path, questions, answers, key); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}

	got, err := OpenVaultKey(path, answers)
	if err != nil {
		t.Fatalf("OpenVaultKey: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key = %q, want %q", got, key)
	}

	// Answer matching is lenient about case and spacing.
	got, err = OpenVaultKey(path, []string{"  smith ", "FLUFFY", "kuala   lumpur"})
	if err != nil {
		t.Fatalf("OpenVaultKey (normalized): %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("normalized key = %q", got)
	}
}

func TestOpenVaultKeyWrongAnswers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	questions, answers := testQA()
	if err := Setup(path, questions, answers, []byte("key-key-key-key-key-key-key-12")); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if _, err := OpenVaultKey(path, []string{"Wrong", "Answers", "Here"}); !errors.Is(err, ErrInvalidAnswer) {
		t.Fatalf("err = %v, want ErrInvalidAnswer", err)
	}
	if _, err := OpenVaultKey(path, []string{"ab", "cd", "ef"}); !errors.Is(err, ErrBadAnswers) {
		t.Fatalf("short answers err = %v, want ErrBadAnswers", err)
	}
}

func TestTamperedQuestionsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	questions, answers := testQA()
	if err := Setup(path, questions, answers, []byte("key-key-key-key-key-key-key-12")); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Swap a question in the file; the AAD binds it, so opening must fail.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	qs, _ := data["questions"].([]any)
	if len(qs) != 3 {
		t.Fatalf("questions in file = %v", data["questions"])
	}
	qs[0] = "Something else entirely?"
	raw, _ = json.Marshal(data)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := OpenVaultKey(path, answers); err == nil {
		t.Fatal("tampered questions must not unlock the key")
	}
}

func TestValidateQuestions(t *testing.T) {
	q := []string{Questions[0], Questions[1], Questions[2]}
	if err := ValidateQuestions(q); err != nil {
		t.Fatalf("valid questions rejected: %v", err)
	}
	if err := ValidateQuestions(q[:2]); !errors.Is(err, ErrBadQuestions) {
		t.Fatalf("two questions err = %v", err)
	}
	if err := ValidateQuestions([]string{Questions[0], Questions[0], Questions[2]}); !errors.Is(err, ErrBadQuestions) {
		t.Fatalf("duplicate questions err = %v", err)
	}
	if err := ValidateQuestions([]string{"not a question", Questions[1], Questions[2]}); !errors.Is(err, ErrBadQuestions) {
		t.Fatalf("unknown question err = %v", err)
	}
}

func TestNotConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	if _, err := QuestionsFor(path); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if Configured(path) {
		t.Fatal("Configured should be false")
	}
	if err := Remove(path); err != nil {
		t.Fatalf("Remove on missing file: %v", err)
	}
}

func TestRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	questions, answers := testQA()
	if err := Setup(path, questions, answers, []byte("key-key-key-key-key-key-key-12")); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !Configured(path) {
		t.Fatal("Configured should be true")
	}
	if err := Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if Configured(path) {
		t.Fatal("Configured should be false after Remove")
	}
}

func TestAnswerThresholdTwoOfThree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	questions, answers := testQA()
	if err := Setup(path, questions, answers, []byte("key-key-key-key-key-key-key-12")); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Two correct + one wrong is enough.
	two := []string{answers[0], answers[1], "totally-wrong-answer"}
	key, err := OpenVaultKey(path, two)
	if err != nil {
		t.Fatalf("2-of-3 should succeed: %v", err)
	}
	if string(key) != "key-key-key-key-key-key-key-12" {
		t.Fatalf("key = %q", key)
	}

	// One correct answer is never enough.
	one := []string{answers[0], "totally-wrong-one", "totally-wrong-two"}
	if _, err := OpenVaultKey(path, one); !errors.Is(err, ErrInvalidAnswer) {
		t.Fatalf("1-of-3 err = %v, want ErrInvalidAnswer", err)
	}
	// None correct fails too.
	zero := []string{"wrong-a-answer", "wrong-b-answer", "wrong-c-answer"}
	if _, err := OpenVaultKey(path, zero); !errors.Is(err, ErrInvalidAnswer) {
		t.Fatalf("0-of-3 err = %v, want ErrInvalidAnswer", err)
	}
}

func TestRecoveryKeyRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	vaultKey := []byte("key-key-key-key-key-key-key-12")

	key, err := SetupKey(path, vaultKey)
	if err != nil {
		t.Fatalf("SetupKey: %v", err)
	}
	normalized := NormalizeRecoveryKey(key)
	if len(normalized) != KeyLength {
		t.Fatalf("key %q normalizes to %d chars", key, len(normalized))
	}
	if !HasKey(path) {
		t.Fatal("HasKey should be true")
	}
	got, err := OpenVaultKeyWithRecoveryKey(path, key)
	if err != nil {
		t.Fatalf("open with key: %v", err)
	}
	if string(got) != string(vaultKey) {
		t.Fatalf("key = %q", got)
	}
	// Case and hyphens do not matter.
	if _, err := OpenVaultKeyWithRecoveryKey(path, strings.ToUpper(key)); err != nil {
		t.Fatalf("open with upper key: %v", err)
	}
	// Wrong keys fail.
	if _, err := OpenVaultKeyWithRecoveryKey(path, "deadbeef-deadbeef-deadbeef-deadbeef-deadbeef-deadbeef-deadbeef-deadbeef"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("wrong key err = %v, want ErrInvalidKey", err)
	}
	if _, err := OpenVaultKeyWithRecoveryKey(path, "too-short"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short key err = %v, want ErrInvalidKey", err)
	}
}

func TestSetupKeyPreservesQuestions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	questions, answers := testQA()
	if err := Setup(path, questions, answers, []byte("key-key-key-key-key-key-key-12")); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if _, err := SetupKey(path, []byte("key-key-key-key-key-key-key-12")); err != nil {
		t.Fatalf("SetupKey: %v", err)
	}
	got, err := QuestionsFor(path)
	if err != nil {
		t.Fatalf("questions lost: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("questions = %v", got)
	}
	// Answers still work alongside the key.
	if _, err := OpenVaultKey(path, answers); err != nil {
		t.Fatalf("answers after SetupKey: %v", err)
	}
}

func TestClearKeyAndClearQuestions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	questions, answers := testQA()
	vaultKey := []byte("key-key-key-key-key-key-key-12")
	if err := Setup(path, questions, answers, vaultKey); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	key, err := SetupKey(path, vaultKey)
	if err != nil {
		t.Fatalf("SetupKey: %v", err)
	}

	if err := ClearKey(path); err != nil {
		t.Fatalf("ClearKey: %v", err)
	}
	if HasKey(path) {
		t.Fatal("key still present")
	}
	if _, err := OpenVaultKey(path, answers); err != nil {
		t.Fatalf("answers must survive ClearKey: %v", err)
	}
	if _, err := OpenVaultKeyWithRecoveryKey(path, key); !errors.Is(err, ErrNoKey) {
		t.Fatalf("key open err = %v, want ErrNoKey", err)
	}

	// Clearing the last credential removes the file.
	if err := ClearQuestions(path); err != nil {
		t.Fatalf("ClearQuestions: %v", err)
	}
	if Configured(path) {
		t.Fatal("file should be gone when nothing is left")
	}
}

func TestRewrapKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	key, err := SetupKey(path, []byte("old-key-old-key-old-key-old-"))
	if err != nil {
		t.Fatalf("SetupKey: %v", err)
	}
	if err := RewrapKey(path, key, []byte("new-key-new-key-new-key-new-")); err != nil {
		t.Fatalf("RewrapKey: %v", err)
	}
	got, err := OpenVaultKeyWithRecoveryKey(path, key)
	if err != nil {
		t.Fatalf("open after rewrap: %v", err)
	}
	if string(got) != "new-key-new-key-new-key-new-" {
		t.Fatalf("key = %q", got)
	}
}
