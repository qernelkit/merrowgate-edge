// Package enrol registers the gateway with the Merrowgate device CA. On first start
// it creates the gateway's device key, sends a certificate request through the cloud
// upstream, and stores the certificate the CA returns next to the key in state_dir.
package enrol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Files under state_dir.
const (
	keyFile     = "device.key"
	requestFile = "device.req"
	issuedFile  = "device.pem"
)

// Submitter sends a request to the cloud and returns the issued chain (PEM), or
// nil while the request is waiting for approval.
type Submitter interface {
	PostJSON(ctx context.Context, path string, v, out any) error
}

// Enroller runs enrolment for one gateway.
type Enroller struct {
	dir       string
	gatewayID string
	site      string
	cloud     Submitter
}

// New returns an Enroller that keeps its files in dir.
func New(dir, gatewayID, site string, cloud Submitter) *Enroller {
	return &Enroller{dir: dir, gatewayID: gatewayID, site: site, cloud: cloud}
}

// Enrolled reports whether the gateway already holds an issued certificate.
func (e *Enroller) Enrolled() bool {
	_, err := os.Stat(filepath.Join(e.dir, issuedFile))
	return err == nil
}

// Prepare creates the device key and request on first start. A request left by an
// earlier start is kept, so the CA operator sees one request per gateway.
func (e *Enroller) Prepare() error {
	if _, err := os.Stat(filepath.Join(e.dir, requestFile)); err == nil {
		log.Printf("enrolment certificate request queued for %s", e.gatewayID)
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("enrol: device key: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         e.gatewayID,
			Organization:       []string{"Merrowgate Systems"},
			OrganizationalUnit: []string{"depot " + e.site},
		},
		DNSNames:           []string{e.gatewayID + ".edge.merrowgate.example"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	req, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return fmt.Errorf("enrol: request: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("enrol: device key: %w", err)
	}
	if err := writePEM(filepath.Join(e.dir, keyFile), "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	return writePEM(filepath.Join(e.dir, requestFile), "CERTIFICATE REQUEST", req, 0o644)
}

// Submit sends the queued request and stores the result once the CA has issued it.
// It returns false while the request is still waiting for an operator.
func (e *Enroller) Submit(ctx context.Context) (bool, error) {
	raw, err := os.ReadFile(filepath.Join(e.dir, requestFile))
	if err != nil {
		return false, fmt.Errorf("enrol: %w", err)
	}
	var reply struct {
		Status string `json:"status"`
		Chain  string `json:"chain"`
	}
	body := map[string]string{"gateway": e.gatewayID, "site": e.site, "request": string(raw)}
	if err := e.cloud.PostJSON(ctx, "/v1/enrol", body, &reply); err != nil {
		return false, err
	}
	if reply.Status != "issued" {
		return false, nil
	}
	if err := os.WriteFile(filepath.Join(e.dir, issuedFile), []byte(reply.Chain), 0o644); err != nil {
		return false, fmt.Errorf("enrol: %w", err)
	}
	return true, nil
}

// Wait submits the request every interval until it is issued or ctx ends.
func (e *Enroller) Wait(ctx context.Context, interval time.Duration) {
	for {
		done, err := e.Submit(ctx)
		switch {
		case done:
			log.Printf("enrolment complete for %s", e.gatewayID)
			return
		case err != nil:
			log.Printf("enrolment: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func writePEM(path, kind string, der []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("enrol: %s already exists; remove it to enrol again", path)
	}
	if err != nil {
		return fmt.Errorf("enrol: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: kind, Bytes: der}); err != nil {
		f.Close()
		return fmt.Errorf("enrol: %w", err)
	}
	return f.Close()
}
