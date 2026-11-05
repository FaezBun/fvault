package crypto

import (
	"bytes"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := RandomBytes(KeyLen)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	return key
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("correct horse battery staple")
	aad := []byte("context")

	nonce, ciphertext, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext matches plaintext")
	}

	got, err := Open(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestOpenWrongKey(t *testing.T) {
	key := testKey(t)
	nonce, ciphertext, err := Seal(key, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(testKey(t), nonce, ciphertext, nil); err == nil {
		t.Fatal("expected an error with the wrong key")
	}
}

func TestOpenTamperedCiphertext(t *testing.T) {
	key := testKey(t)
	nonce, ciphertext, err := Seal(key, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ciphertext[0] ^= 0xff
	if _, err := Open(key, nonce, ciphertext, nil); err == nil {
		t.Fatal("expected an error with tampered ciphertext")
	}
}

func TestOpenWrongAAD(t *testing.T) {
	key := testKey(t)
	nonce, ciphertext, err := Seal(key, []byte("secret"), []byte("one"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(key, nonce, ciphertext, []byte("two")); err == nil {
		t.Fatal("expected an error with different AAD")
	}
}

func TestOpenInvalidNonce(t *testing.T) {
	if _, err := Open(testKey(t), []byte("short"), []byte("data"), nil); err == nil {
		t.Fatal("expected an error for an invalid nonce")
	}
}

func TestDefaultParamsValid(t *testing.T) {
	p := DefaultParams()
	if !p.Valid() {
		t.Fatalf("default params are invalid: %+v", p)
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	p := Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	a := DeriveKey("password", salt, p)
	b := DeriveKey("password", salt, p)
	if !bytes.Equal(a, b) {
		t.Fatal("DeriveKey is not deterministic")
	}
	if len(a) != KeyLen {
		t.Fatalf("key length = %d, want %d", len(a), KeyLen)
	}
	if bytes.Equal(a, DeriveKey("other", salt, p)) {
		t.Fatal("different passwords produced the same key")
	}
}
