package recovery

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
