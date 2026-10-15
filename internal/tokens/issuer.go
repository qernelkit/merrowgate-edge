// Package tokens issues the bearer tokens that depot devices present to the
// control API and to the device portal. The algorithm, issuer and lifetime come
// from the tokens section of gateway.yaml; the key is pki_dir/token-signing.key.
package tokens

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"merrowgate.example/edge/internal/config"
)

// KeyFile is the token key's file name under pki_dir.
const KeyFile = "token-signing.key"

// ErrRejected is returned for any token that does not verify; the reason is logged,
// never sent to the client.
var ErrRejected = errors.New("tokens: token rejected")

// Issuer signs and checks device tokens.
type Issuer struct {
	method jwt.SigningMethod
	key    *ecdsa.PrivateKey
	issuer string
	ttl    time.Duration
}

// NewIssuer loads the token key and checks the configured algorithm.
func NewIssuer(cfg *config.Config) (*Issuer, error) {
	method := jwt.GetSigningMethod(cfg.Tokens.Algorithm)
	if method == nil {
		return nil, fmt.Errorf("tokens.algorithm: unknown algorithm %q", cfg.Tokens.Algorithm)
	}
	raw, err := os.ReadFile(cfg.PKIPath(KeyFile))
	if err != nil {
		return nil, fmt.Errorf("tokens: %w", err)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("tokens: %s: %w", KeyFile, err)
	}
	return &Issuer{method: method, key: key, issuer: cfg.Tokens.Issuer, ttl: cfg.Tokens.TTL}, nil
}

// Issue returns a token for a device at a site, granting scopes.
func (i *Issuer) Issue(deviceID, site string, scopes []string, now time.Time) (string, error) {
	id, err := newTokenID()
	if err != nil {
		return "", err
	}
	claims := DeviceClaims{
		Site:   site,
		Scopes: scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			Issuer:    i.issuer,
			Subject:   deviceID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}
	signed, err := jwt.NewWithClaims(i.method, claims).SignedString(i.key)
	if err != nil {
		return "", fmt.Errorf("tokens: sign for %s: %w", deviceID, err)
	}
	return signed, nil
}

// Check verifies a token and returns its claims.
func (i *Issuer) Check(raw string) (*DeviceClaims, error) {
	var claims DeviceClaims
	_, err := jwt.ParseWithClaims(raw, &claims, i.verificationKey,
		jwt.WithValidMethods([]string{i.method.Alg()}),
		jwt.WithIssuer(i.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: no subject", ErrRejected)
	}
	return &claims, nil
}

func (i *Issuer) verificationKey(*jwt.Token) (any, error) {
	return i.key.Public(), nil
}

// newTokenID returns a random token ID (the jti claim), used to revoke one token.
func newTokenID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("tokens: id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TTL is how long issued tokens stay valid.
func (i *Issuer) TTL() time.Duration { return i.ttl }
