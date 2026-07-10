// Package crypto provides SSH host key management: loading existing host
// keys from disk or generating new ones on first run, matching OpenSSH's
// ssh-keygen-on-demand behavior. It is a thin wrapper over
// golang.org/x/crypto/ssh and the standard library crypto packages.
package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// minRSAKeyBits is the minimum RSA modulus size accepted for host keys and
// used when generating new RSA host keys, matching modern OpenSSH guidance.
const minRSAKeyBits = 2048

// generatedRSAKeyBits is the RSA key size used when generating a new RSA
// host key, matching the current ssh-keygen default.
const generatedRSAKeyBits = 3072

// HostKeyManager loads SSH host keys from the configured file paths,
// generating and persisting a new key pair for any path that does not yet
// exist, mirroring OpenSSH's automatic host key generation.
type HostKeyManager struct {
	paths []string
}

// NewHostKeyManager creates a HostKeyManager for the given host key file
// paths.
func NewHostKeyManager(paths []string) *HostKeyManager {
	return &HostKeyManager{paths: paths}
}

// LoadOrGenerateKeys loads each configured host key file, generating and
// persisting a new key (type inferred from the file name, defaulting to
// Ed25519) when the file does not already exist. Empty paths are skipped.
func (m *HostKeyManager) LoadOrGenerateKeys() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, path := range m.paths {
		if path == "" {
			continue
		}

		signer, err := loadOrGenerateKey(path)
		if err != nil {
			return nil, fmt.Errorf("host key %s: %w", path, err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

// loadOrGenerateKey loads an existing private key file, or generates and
// persists a new one if the file does not exist.
func loadOrGenerateKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, parseErr := ssh.ParsePrivateKey(data)
		if parseErr != nil {
			return nil, fmt.Errorf("parse existing key: %w", parseErr)
		}
		return signer, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	return generateAndSaveKey(path)
}

// generateAndSaveKey generates a new private key (type inferred from path),
// persists it to disk with restrictive permissions, and returns a Signer.
func generateAndSaveKey(path string) (ssh.Signer, error) {
	priv, err := generatePrivateKey(keyTypeFromPath(path))
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create key directory: %w", err)
		}
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	return signer, nil
}

// generatePrivateKey creates a new private key of the requested type.
// Unrecognized types (including the deprecated "dsa") default to Ed25519,
// the current recommended default for new host keys.
func generatePrivateKey(keyType string) (any, error) {
	switch keyType {
	case "rsa":
		return rsa.GenerateKey(rand.Reader, generatedRSAKeyBits)
	case "ecdsa":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
}

// keyTypeFromPath infers the intended key type from a host key file name,
// e.g. "ssh_host_rsa_key" -> "rsa". Returns "" if no known type is found.
func keyTypeFromPath(path string) string {
	filename := filepath.Base(path)
	switch {
	case strings.Contains(filename, "ed25519"):
		return "ed25519"
	case strings.Contains(filename, "ecdsa"):
		return "ecdsa"
	case strings.Contains(filename, "rsa"):
		return "rsa"
	case strings.Contains(filename, "dsa"):
		return "dsa"
	default:
		return ""
	}
}

// ValidateHostKey checks that a host key Signer is usable: non-nil, has a
// non-nil public key of a supported algorithm, and (for RSA keys) meets the
// minimum modulus size.
func ValidateHostKey(signer ssh.Signer) error {
	if signer == nil {
		return errors.New("host key signer is nil")
	}

	pub := signer.PublicKey()
	if pub == nil {
		return errors.New("host key has no public key")
	}

	switch pub.Type() {
	case ssh.KeyAlgoRSA:
		return validateRSAKeySize(pub)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoED25519:
		return nil
	case ssh.InsecureKeyAlgoDSA:
		return fmt.Errorf("unsupported host key type: %s (DSA is deprecated and insecure)", pub.Type())
	default:
		return fmt.Errorf("unsupported host key type: %s", pub.Type())
	}
}

// validateRSAKeySize verifies an RSA public key meets the minimum modulus
// size requirement.
func validateRSAKeySize(pub ssh.PublicKey) error {
	cryptoPub, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return errors.New("cannot inspect RSA key: unsupported public key implementation")
	}

	rsaPub, ok := cryptoPub.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return errors.New("cannot inspect RSA key: unexpected underlying key type")
	}

	if rsaPub.N.BitLen() < minRSAKeyBits {
		return fmt.Errorf("RSA host key too small: %d bits (minimum %d)", rsaPub.N.BitLen(), minRSAKeyBits)
	}
	return nil
}

// GetKeyFingerprint returns the SSH SHA256 fingerprint of a public key,
// matching the format used by `ssh-keygen -l`.
func GetKeyFingerprint(pub ssh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

// GetKeyType returns the SSH key algorithm name of a public key (e.g.
// "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256").
func GetKeyType(pub ssh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return pub.Type()
}
