// Package webhook delivers depot events (door alarms, device faults, firmware
// rollouts) to the operator endpoints listed in gateway.yaml.
//
// Every delivery carries X-Merrowgate-Signature: t=<unix seconds>,v1=<hex>. The
// MAC covers "<unix seconds>." followed by the body, so a receiver can reject
// replays by the timestamp and check the body with its copy of the secret.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"merrowgate.example/edge/internal/config"
)

// Scheme is the webhooks.signature value this version understands.
const Scheme = "hmac-sha256"

// SignatureHeader carries the delivery signature.
const SignatureHeader = "X-Merrowgate-Signature"

// Event is one depot event.
type Event struct {
	Kind   string            `json:"kind"`
	Site   string            `json:"site"`
	Device string            `json:"device,omitempty"`
	At     time.Time         `json:"at"`
	Detail map[string]string `json:"detail,omitempty"`
}

// Sender signs and posts events.
type Sender struct {
	secret    []byte
	endpoints []string
	client    *http.Client
}

// CheckConfig reports whether this version understands the webhooks section of
// gateway.yaml.
func CheckConfig(cfg config.Webhooks) error {
	if cfg.Signature != Scheme {
		return fmt.Errorf("webhooks.signature: unsupported scheme %q", cfg.Signature)
	}
	return nil
}

// NewSender returns a sender for the configured endpoints.
func NewSender(cfg config.Webhooks, secret []byte) (*Sender, error) {
	if err := CheckConfig(cfg); err != nil {
		return nil, err
	}
	if len(secret) < 32 {
		return nil, errors.New("webhooks: the shared secret must be at least 32 bytes")
	}
	return &Sender{
		secret:    secret,
		endpoints: cfg.Endpoints,
		client:    &http.Client{Timeout: cfg.Timeout},
	}, nil
}

// Off returns a sender with no endpoints, for a gateway whose shared secret has
// not been provisioned yet.
func Off() *Sender {
	return &Sender{}
}

// Header returns the signature header value for body sent at ts.
func (s *Sender) Header(ts time.Time, body []byte) string {
	mac := hmac.New(sha256.New, s.secret)
	fmt.Fprintf(mac, "%d.", ts.Unix())
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

// Send posts ev to every endpoint, retrying each up to three times. It returns the
// first error after logging every failure.
func (s *Sender) Send(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	var first error
	for _, ep := range s.endpoints {
		if err := s.deliver(ctx, ep, body); err != nil {
			log.Printf("webhook %s to %s: %v", ev.Kind, ep, err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func (s *Sender) deliver(ctx context.Context, endpoint string, body []byte) error {
	var err error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		if err = s.post(ctx, endpoint, body); err == nil {
			return nil
		}
	}
	return err
}

func (s *Sender) post(ctx context.Context, endpoint string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, s.Header(time.Now(), body))
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("endpoint answered %s", resp.Status)
	}
	return nil
}
