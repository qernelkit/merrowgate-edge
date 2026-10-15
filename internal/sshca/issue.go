// Package sshca issues short-lived SSH user certificates to field engineers for
// the depot bastion. The authority key is created on the gateway's first start and
// stays in state_dir; it never leaves the gateway.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Authority signs engineer certificates.
type Authority struct {
	signer ssh.Signer
	ttl    time.Duration
}

// LoadOrCreate reads the authority key at path, creating it on first start.
func LoadOrCreate(path string, ttl time.Duration) (*Authority, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return create(path, ttl)
	}
	if err != nil {
		return nil, fmt.Errorf("sshca: %w", err)
	}
	parsed, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("sshca: %s: %w", path, err)
	}
	caKey, ok := parsed.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("sshca: %s: unexpected key type %T", path, parsed)
	}
	return newAuthority(*caKey, ttl)
}

func create(path string, ttl time.Duration) (*Authority, error) {
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshca: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(caKey, "merrowgate engineer access")
	if err != nil {
		return nil, fmt.Errorf("sshca: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("sshca: %w", err)
	}
	return newAuthority(caKey, ttl)
}

func newAuthority(caKey ed25519.PrivateKey, ttl time.Duration) (*Authority, error) {
	signer, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: %w", err)
	}
	return &Authority{signer: signer, ttl: ttl}, nil
}

// AuthorizedKey is the authority line for sshd's TrustedUserCAKeys.
func (a *Authority) AuthorizedKey() []byte {
	return ssh.MarshalAuthorizedKey(a.signer.PublicKey())
}

// Issue signs an engineer's key (an authorized_keys line) for the configured
// lifetime, for the given principals, and returns the certificate line.
func (a *Authority) Issue(engineer string, authorizedKey []byte, principals []string) ([]byte, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: engineer key: %w", err)
	}
	if strings.ContainsAny(engineer, " \t\n") {
		return nil, errors.New("sshca: engineer login must not contain spaces")
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, fmt.Errorf("sshca: %w", err)
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("%s@%s", engineer, now.UTC().Format("20060102T150405Z")),
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-2 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(a.ttl).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-pty":             "",
			"permit-port-forwarding": "",
		}},
	}
	if err := cert.SignCert(rand.Reader, a.signer); err != nil {
		return nil, fmt.Errorf("sshca: sign: %w", err)
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}
