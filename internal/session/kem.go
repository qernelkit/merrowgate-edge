// Package session sets up the keys depot devices use with the gateway.
//
// A device opens a session by fetching the gateway's current encapsulation key,
// encapsulating to it, and posting the ciphertext; both sides then hold the same
// 32-byte session key, which seals the device's telemetry until the next session.
// The gateway's key pair is replaced every day; sessions opened under the previous
// pair stay valid until they expire.
package session

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrUnknownKey means the device encapsulated to a key the gateway no longer holds.
var ErrUnknownKey = errors.New("session: encapsulation key has been replaced")

// Keyring holds the gateway's current and previous decapsulation keys.
type Keyring struct {
	mu       sync.RWMutex
	current  *mlkem.DecapsulationKey768
	previous *mlkem.DecapsulationKey768
	rotated  time.Time
}

// NewKeyring creates the first key pair.
func NewKeyring() (*Keyring, error) {
	k := &Keyring{}
	if err := k.Rotate(time.Now()); err != nil {
		return nil, err
	}
	return k, nil
}

// Rotate replaces the current key pair, keeping the old one for late sessions.
func (k *Keyring) Rotate(now time.Time) error {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return fmt.Errorf("session: new key pair: %w", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.previous, k.current = k.current, dk
	k.rotated = now
	return nil
}

// Published returns the key devices encapsulate to, and when it was created.
func (k *Keyring) Published() ([]byte, time.Time) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current.EncapsulationKey().Bytes(), k.rotated
}

// Accept decapsulates a device's ciphertext and returns the session key. Devices
// send the first eight bytes of the key they used, so the gateway knows which pair
// to try.
func (k *Keyring) Accept(keyHint, ciphertext []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, dk := range []*mlkem.DecapsulationKey768{k.current, k.previous} {
		if dk == nil || !hasPrefix(dk.EncapsulationKey().Bytes(), keyHint) {
			continue
		}
		shared, err := dk.Decapsulate(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}
		return shared, nil
	}
	return nil, ErrUnknownKey
}

func hasPrefix(key, hint []byte) bool {
	return len(hint) >= 8 && bytes.HasPrefix(key, hint)
}

// RotateDaily replaces the key pair once a day until stop is closed.
func (k *Keyring) RotateDaily(stop <-chan struct{}, logf func(string, ...any)) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			if err := k.Rotate(now); err != nil {
				logf("session key rotation: %v", err)
			}
		}
	}
}
