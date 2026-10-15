package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"merrowgate.example/edge/internal/config"
)

// receiverHeader computes the header the way the integration guide tells
// operators to check it on their side.
func receiverHeader(secret []byte, ts time.Time, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(fmt.Sprintf("%d.", ts.Unix())))
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func newTestSender(t *testing.T) (*Sender, []byte) {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(config.Webhooks{Signature: Scheme, Timeout: time.Second}, secret)
	if err != nil {
		t.Fatal(err)
	}
	return s, secret
}

func TestHeaderMatchesReceiver(t *testing.T) {
	s, secret := newTestSender(t)
	ts := time.Date(2026, 3, 2, 14, 30, 0, 0, time.UTC)
	body := []byte(`{"kind":"door.open","site":"SLC","at":"2026-03-02T14:30:00Z"}`)
	if got, want := s.Header(ts, body), receiverHeader(secret, ts, body); got != want {
		t.Errorf("Header = %s, want %s", got, want)
	}
}

func TestHeaderCoversTimestamp(t *testing.T) {
	s, _ := newTestSender(t)
	body := []byte(`{"kind":"device.fault"}`)
	ts := time.Unix(1772461800, 0)
	if s.Header(ts, body) == s.Header(ts.Add(time.Second), body) {
		t.Error("headers for different timestamps are equal")
	}
}

func TestNewSenderRejectsShortSecret(t *testing.T) {
	if _, err := NewSender(config.Webhooks{Signature: Scheme}, make([]byte, 16)); err == nil {
		t.Error("NewSender accepted a 16-byte secret")
	}
}
