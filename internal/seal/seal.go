// Package seal protects gateway state at rest: the admin account store and the
// other files edgectl keeps under state_dir, plus the token a device receives
// when it pairs.
//
// A sealed value is "mgs2." followed by base64 of salt | nonce | ciphertext. The
// key is derived from a 32-byte master secret and the per-value salt, so the
// master secret itself never encrypts anything.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	prefix  = "mgs2."
	saltLen = 16
	keyLen  = 32
)

// ErrOpen means a sealed value could not be opened: wrong master secret, or the
// value was cut short or altered.
var ErrOpen = errors.New("seal: cannot open value")

// Seal encrypts plaintext under a key derived from master and a fresh salt.
func Seal(master, plaintext []byte) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	key, err := deriveKey(master, salt)
	if err != nil {
		return "", err
	}
	box, err := SealWithKey(key, plaintext)
	if err != nil {
		return "", err
	}
	return prefix + base64.StdEncoding.EncodeToString(append(salt, box...)), nil
}

// Open reverses Seal.
func Open(master []byte, sealed string) ([]byte, error) {
	body, ok := strings.CutPrefix(sealed, prefix)
	if !ok {
		return nil, fmt.Errorf("%w: not a sealed value", ErrOpen)
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(raw) < saltLen {
		return nil, fmt.Errorf("%w: malformed", ErrOpen)
	}
	key, err := deriveKey(master, raw[:saltLen])
	if err != nil {
		return nil, err
	}
	return OpenWithKey(key, raw[saltLen:])
}

// SealWithKey encrypts plaintext under key and returns nonce | ciphertext.
func SealWithKey(key, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// OpenWithKey opens nonce | ciphertext under a key the caller already holds. The
// v1 import uses it with the key from the operator's export passphrase.
func OpenWithKey(key, box []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(box) < n+aead.Overhead() {
		return nil, fmt.Errorf("%w: too short", ErrOpen)
	}
	plain, err := aead.Open(nil, box[:n], box[n:], nil)
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}

func deriveKey(master, salt []byte) ([]byte, error) {
	if len(master) < 32 {
		return nil, errors.New("seal: master secret must be at least 32 bytes")
	}
	key, err := hkdf.Key(sha256.New, master, salt, "merrowgate config seal v2", keyLen)
	if err != nil {
		return nil, fmt.Errorf("seal: derive: %w", err)
	}
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("seal: key is %d bytes, want %d", len(key), keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return aead, nil
}
