package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Upstream is the gateway's client for the Merrowgate cloud: enrolment, telemetry
// archives and audit shipping. The cloud's load balancers still serve TLS 1.2 to
// older gateways, so the floor is 1.2 with an ECDSA-only suite list. The
// Merrowgate root is in the system bundle (the image appends it at build time).
type Upstream struct {
	base   *url.URL
	client *http.Client
	agent  string
}

// NewUpstream returns a client for the cloud API at baseURL.
func NewUpstream(baseURL string, timeout time.Duration, gatewayID string) (*Upstream, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		ServerName: u.Hostname(),
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	return &Upstream{
		base:   u,
		client: &http.Client{Transport: transport, Timeout: timeout},
		agent:  "edgectl/" + gatewayID,
	}, nil
}

// Put uploads body to path on the cloud API.
func (u *Upstream) Put(ctx context.Context, path, contentType string, body []byte) error {
	_, err := u.do(ctx, http.MethodPut, path, contentType, body)
	return err
}

// PostJSON sends v as JSON to path and decodes the JSON reply into out (if not nil).
func (u *Upstream) PostJSON(ctx context.Context, path string, v, out any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("upstream: %s: %w", path, err)
	}
	reply, err := u.do(ctx, http.MethodPost, path, "application/json", body)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(reply, out); err != nil {
		return fmt.Errorf("upstream: %s: bad reply: %w", path, err)
	}
	return nil
}

func (u *Upstream) do(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	target := u.base.JoinPath(path)
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", u.agent)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("upstream: %s %s: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("upstream: %s %s: %s", method, path, resp.Status)
	}
	return reply, nil
}
