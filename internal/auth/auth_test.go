package auth

import (
	"context"
	"crypto/rand"
	"io"
	"testing"
)

func TestDecryptWithKeyStrictRejectsMalformedCiphertext(t *testing.T) {
	a := New(noopStore{}, "admin", "/x", 50, false)
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}

	if got, err := a.DecryptWithKeyStrict(key, "not-base64"); err == nil {
		t.Fatalf("DecryptWithKeyStrict returned %q, nil; want error", got)
	}
}

func TestDecryptWithKeyStrictAllowsEmptyField(t *testing.T) {
	a := New(noopStore{}, "admin", "/x", 50, false)
	got, err := a.DecryptWithKeyStrict(nil, "")
	if err != nil {
		t.Fatalf("DecryptWithKeyStrict empty unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("DecryptWithKeyStrict empty = %q, want empty", got)
	}
}

func TestDecryptWithKeyStrictRejectsNonEmptyFieldWithoutKey(t *testing.T) {
	a := New(noopStore{}, "admin", "/x", 50, false)
	if got, err := a.DecryptWithKeyStrict(nil, "secret"); err == nil {
		t.Fatalf("DecryptWithKeyStrict returned %q, nil; want error", got)
	}
}

type noopStore struct{}

func (noopStore) VerifyPassword(context.Context, string, string) bool { return false }
func (noopStore) ChangePassword(context.Context, string, string, string) error {
	return nil
}
func (noopStore) HasTOTPEnabled(context.Context, string) (bool, error) { return false, nil }
func (noopStore) GetTOTPSecret(context.Context, string) (string, error) {
	return "", nil
}
func (noopStore) SetTOTPSecret(context.Context, string, string) error { return nil }
func (noopStore) DisableTOTP(context.Context, string) error           { return nil }
