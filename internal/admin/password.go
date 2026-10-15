// Package admin keeps the gateway's local admin accounts: depot supervisors and
// field engineers who sign in to the control API.
package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"merrowgate.example/edge/internal/config"
)

const (
	saltLen = 16
	hashLen = 32
)

// ErrMismatch means the password does not match the stored hash.
var ErrMismatch = errors.New("admin: password does not match")

// Hasher hashes passwords with the scheme and cost from the admin section of
// gateway.yaml.
type Hasher struct {
	time    uint32
	memory  uint32
	threads uint8
}

// NewHasher checks the configured scheme and cost.
func NewHasher(cfg config.Admin) (*Hasher, error) {
	if cfg.PasswordHash != "argon2id" {
		return nil, fmt.Errorf("admin: unsupported password hash scheme %q", cfg.PasswordHash)
	}
	if cfg.Time < 1 || cfg.MemoryKiB < 19*1024 || cfg.Threads < 1 {
		return nil, errors.New("admin: time, memory_kib (at least 19456) and threads must be set")
	}
	return &Hasher{time: cfg.Time, memory: cfg.MemoryKiB, threads: cfg.Threads}, nil
}

// Hash returns the stored form of a new password.
func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("admin: %w", err)
	}
	sum := derive([]byte(password), salt, h.time, h.memory, h.threads)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads, b64.EncodeToString(salt), b64.EncodeToString(sum)), nil
}

// Verify checks password against a stored hash. Accounts imported from a v1
// appliance still hold a bcrypt hash; for those, and for hashes made with a lower
// cost than configured, rehash is true and the caller stores a fresh Hash.
func (h *Hasher) Verify(stored, password string) (rehash bool, err error) {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") {
		if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)); err != nil {
			return false, ErrMismatch
		}
		return true, nil
	}
	p, salt, want, err := parseHash(stored)
	if err != nil {
		return false, err
	}
	got := derive([]byte(password), salt, p.time, p.memory, p.threads)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, ErrMismatch
	}
	return p.time < h.time || p.memory < h.memory, nil
}

func derive(password, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, hashLen)
}

type params struct {
	time    uint32
	memory  uint32
	threads uint8
}

func parseHash(stored string) (params, []byte, []byte, error) {
	var p params
	bad := errors.New("admin: unrecognised password hash format")
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, bad
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, bad
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return p, nil, nil, bad
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, bad
	}
	sum, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(sum) != hashLen {
		return p, nil, nil, bad
	}
	return p, salt, sum, nil
}
