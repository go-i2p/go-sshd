package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNewHostKeyManager(t *testing.T) {
	m := NewHostKeyManager([]string{"/tmp/a", "/tmp/b"})
	if m == nil {
		t.Fatal("expected non-nil HostKeyManager")
	}
}

func TestLoadOrGenerateKeys_NoPaths(t *testing.T) {
	m := NewHostKeyManager(nil)
	signers, err := m.LoadOrGenerateKeys()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected exactly one ephemeral signer, got %d", len(signers))
	}
	if signers[0].PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("expected default ephemeral key type %s, got %s", ssh.KeyAlgoED25519, signers[0].PublicKey().Type())
	}
}

func TestLoadOrGenerateKeys_EmptyPathsSkipped(t *testing.T) {
	m := NewHostKeyManager([]string{"", ""})
	signers, err := m.LoadOrGenerateKeys()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All paths were empty and skipped, so an ephemeral key is generated.
	if len(signers) != 1 {
		t.Fatalf("expected exactly one ephemeral signer, got %d", len(signers))
	}
}

func TestLoadOrGenerateKeys_GeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		wantType string
	}{
		{"ed25519 by filename", "ssh_host_ed25519_key", ssh.KeyAlgoED25519},
		{"ecdsa by filename", "ssh_host_ecdsa_key", ssh.KeyAlgoECDSA256},
		{"rsa by filename", "ssh_host_rsa_key", ssh.KeyAlgoRSA},
		{"unrecognized filename defaults to ed25519", "ssh_host_key", ssh.KeyAlgoED25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name, tt.filename)
			m := NewHostKeyManager([]string{path})

			signers, err := m.LoadOrGenerateKeys()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(signers) != 1 {
				t.Fatalf("expected 1 signer, got %d", len(signers))
			}
			if signers[0].PublicKey().Type() != tt.wantType {
				t.Errorf("expected key type %s, got %s", tt.wantType, signers[0].PublicKey().Type())
			}

			// The key must have been persisted to disk...
			if _, err := m2Load(path); err != nil {
				t.Fatalf("expected key file to be persisted and loadable: %v", err)
			}

			// ...and loading again must return the same (not regenerated) key.
			signers2, err := NewHostKeyManager([]string{path}).LoadOrGenerateKeys()
			if err != nil {
				t.Fatalf("unexpected error reloading: %v", err)
			}
			if signers2[0].PublicKey().Marshal() == nil ||
				string(signers2[0].PublicKey().Marshal()) != string(signers[0].PublicKey().Marshal()) {
				t.Error("expected reloading an existing key file to return the same key, not regenerate")
			}
		})
	}
}

// m2Load is a small helper that re-parses a persisted key file via the
// package's own loading path, to confirm LoadOrGenerateKeys actually wrote a
// valid, parseable private key to disk.
func m2Load(path string) (ssh.Signer, error) {
	return loadOrGenerateKey(path)
}

func TestValidateHostKey(t *testing.T) {
	signer, err := generateEphemeralKey("ed25519")
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	if err := ValidateHostKey(signer); err != nil {
		t.Errorf("expected valid ed25519 key to pass validation, got: %v", err)
	}

	if err := ValidateHostKey(nil); err == nil {
		t.Error("expected nil signer to fail validation")
	}
}

func TestValidateHostKey_RSASizes(t *testing.T) {
	// A key generated via our own generatePrivateKey uses the modern
	// generatedRSAKeyBits size and must pass validation.
	priv, err := generatePrivateKey("rsa")
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	if err := ValidateHostKey(signer); err != nil {
		t.Errorf("expected modern-size RSA key to pass validation, got: %v", err)
	}
}

func TestGetKeyFingerprintAndType(t *testing.T) {
	signer, err := generateEphemeralKey("ed25519")
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	fp := GetKeyFingerprint(signer.PublicKey())
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}

	kt := GetKeyType(signer.PublicKey())
	if kt != ssh.KeyAlgoED25519 {
		t.Errorf("expected key type %s, got %s", ssh.KeyAlgoED25519, kt)
	}

	if GetKeyFingerprint(nil) != "" {
		t.Error("expected empty fingerprint for nil public key")
	}
	if GetKeyType(nil) != "" {
		t.Error("expected empty key type for nil public key")
	}
}

func TestLoadOrGenerateKeys_InvalidExistingKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad_key")

	if err := os.WriteFile(path, []byte("not a valid private key"), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m := NewHostKeyManager([]string{path})
	if _, err := m.LoadOrGenerateKeys(); err == nil {
		t.Error("expected an error when loading a malformed key file")
	}
}
