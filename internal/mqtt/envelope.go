package mqtt

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

var errShortEnvelope = errors.New("mqtt: sealed reading is too short")

// Envelope opens and seals one device's telemetry with its session key. A sealed
// reading is nonce | ciphertext, with the device ID bound in as additional data so a
// reading cannot be replayed under another device's name.
type Envelope struct {
	aead cipher.AEAD
}

// NewEnvelope returns the envelope for a 32-byte session key.
func NewEnvelope(key []byte) (*Envelope, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("mqtt: session key: %w", err)
	}
	return &Envelope{aead: aead}, nil
}

// Open returns the reading sealed by deviceID.
func (e *Envelope) Open(deviceID string, sealed []byte) ([]byte, error) {
	n := e.aead.NonceSize()
	if len(sealed) < n+e.aead.Overhead() {
		return nil, errShortEnvelope
	}
	reading, err := e.aead.Open(nil, sealed[:n], sealed[n:], []byte(deviceID))
	if err != nil {
		return nil, fmt.Errorf("mqtt: reading from %s does not open: %w", deviceID, err)
	}
	return reading, nil
}

// Seal is the device side of Open.
func (e *Envelope) Seal(deviceID string, reading []byte) ([]byte, error) {
	n := e.aead.NonceSize()
	out := make([]byte, n, n+len(reading)+e.aead.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("mqtt: %w", err)
	}
	return e.aead.Seal(out, out[:n], reading, []byte(deviceID)), nil
}
