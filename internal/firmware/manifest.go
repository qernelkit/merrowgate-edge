// Package firmware checks firmware bundles for depot devices before the gateway
// offers them to devices: the manifest must be signed by the Merrowgate release
// key, and the image must have the size and checksum the manifest lists.
//
// Bundles are dropped into state_dir/firmware/<model>/<version>/ as two files,
// "manifest" and "image".
package firmware

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFile is the release key's file name under pki_dir.
const KeyFile = "firmware-signing.pub"

var (
	ErrSignature = errors.New("firmware: manifest signature does not verify")
	ErrImage     = errors.New("firmware: image does not match its manifest")
)

// Release is what a signed manifest says about one firmware image.
type Release struct {
	Model    string `json:"model"`
	Version  string `json:"version"`
	Size     int64  `json:"size"`
	ImageSum string `json:"image_sum"`
	Notes    string `json:"notes,omitempty"`
}

// Verifier holds the release key.
type Verifier struct {
	key ed25519.PublicKey
}

// LoadVerifier reads the release key from a PEM file.
func LoadVerifier(path string) (*Verifier, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("firmware: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("firmware: %s: no PEM block", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("firmware: %s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("firmware: %s: unexpected key type %T", path, parsed)
	}
	return &Verifier{key: key}, nil
}

// Check verifies a manifest and the image it describes, and returns the release.
func (v *Verifier) Check(manifest *Manifest, image []byte) (*Release, error) {
	if !ed25519.Verify(v.key, manifest.Body, manifest.Signature) {
		return nil, ErrSignature
	}
	var rel Release
	if err := json.Unmarshal(manifest.Body, &rel); err != nil {
		return nil, fmt.Errorf("firmware: manifest body: %w", err)
	}
	if int64(len(image)) != rel.Size {
		return nil, fmt.Errorf("%w: %d bytes, manifest says %d", ErrImage, len(image), rel.Size)
	}
	if imageSum(image) != rel.ImageSum {
		return nil, fmt.Errorf("%w: checksum differs", ErrImage)
	}
	return &rel, nil
}

// CheckBundle reads and checks the bundle in dir.
func (v *Verifier) CheckBundle(dir string) (*Release, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest"))
	if err != nil {
		return nil, fmt.Errorf("firmware: %w", err)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	image, err := os.ReadFile(filepath.Join(dir, "image"))
	if err != nil {
		return nil, fmt.Errorf("firmware: %w", err)
	}
	return v.Check(m, image)
}

// imageSum is the image checksum as release tooling writes it into manifests.
func imageSum(image []byte) string {
	sum := sha256.Sum256(image)
	return hex.EncodeToString(sum[:])
}
