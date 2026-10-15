// Package config loads the gateway settings from /etc/merrowgate/gateway.yaml.
//
// Load checks only what it can check alone (required fields, ranges, paths). Each
// package that consumes a section checks the values it understands when it is
// constructed, so an unsupported value fails at start with the section's name.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"merrowgate.example/edge/internal/depots"
)

// DefaultPath is where the image puts the gateway settings.
const DefaultPath = "/etc/merrowgate/gateway.yaml"

type Config struct {
	Depot       Depot       `yaml:"depot"`
	Listen      Listen      `yaml:"listen"`
	StateDir    string      `yaml:"state_dir"`
	PKIDir      string      `yaml:"pki_dir"`
	Tokens      Tokens      `yaml:"tokens"`
	Admin       Admin       `yaml:"admin"`
	Webhooks    Webhooks    `yaml:"webhooks"`
	Telemetry   Telemetry   `yaml:"telemetry"`
	Upstream    Upstream    `yaml:"upstream"`
	Engineers   Engineers   `yaml:"engineers"`
	Attestation Attestation `yaml:"attestation"`
}

type Depot struct {
	Site      string `yaml:"site"`
	Name      string `yaml:"name"`
	GatewayID string `yaml:"gateway_id"`
}

type Listen struct {
	API string `yaml:"api"`
}

type Tokens struct {
	Issuer    string        `yaml:"issuer"`
	Algorithm string        `yaml:"algorithm"`
	TTL       time.Duration `yaml:"ttl"`
}

type Admin struct {
	PasswordHash string        `yaml:"password_hash"`
	Time         uint32        `yaml:"time"`
	MemoryKiB    uint32        `yaml:"memory_kib"`
	Threads      uint8         `yaml:"threads"`
	LoginTTL     time.Duration `yaml:"login_ttl"`
}

type Webhooks struct {
	Signature  string        `yaml:"signature"`
	SecretFile string        `yaml:"secret_file"`
	Timeout    time.Duration `yaml:"timeout"`
	Endpoints  []string      `yaml:"endpoints"`
}

type Telemetry struct {
	Broker           string  `yaml:"broker"`
	Username         string  `yaml:"username"`
	PasswordFile     string  `yaml:"password_file"`
	TopicBuckets     int     `yaml:"topic_buckets"`
	Workers          int     `yaml:"workers"`
	HashRingReplicas int     `yaml:"hash_ring_replicas"`
	Envelope         string  `yaml:"envelope"`
	Archive          Archive `yaml:"archive"`
}

type Archive struct {
	KeyPrefix string        `yaml:"key_prefix"`
	Bucket    string        `yaml:"bucket"`
	Every     time.Duration `yaml:"every"`
}

type Upstream struct {
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`
}

type Engineers struct {
	CertTTL    time.Duration `yaml:"cert_ttl"`
	Principals []string      `yaml:"principals"`
}

type Attestation struct {
	Required     bool          `yaml:"required"`
	ChallengeTTL time.Duration `yaml:"challenge_ttl"`
}

// Load reads and checks the settings file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg := defaults()
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	if err := cfg.check(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		StateDir:  "/var/lib/merrowgate",
		PKIDir:    "/etc/merrowgate/pki",
		Tokens:    Tokens{TTL: 12 * time.Hour},
		Admin:     Admin{LoginTTL: 30 * time.Minute},
		Webhooks:  Webhooks{Timeout: 10 * time.Second},
		Telemetry: Telemetry{TopicBuckets: 16, Workers: 2, HashRingReplicas: 64, Archive: Archive{Every: time.Hour}},
		Upstream:  Upstream{Timeout: 20 * time.Second},
		Engineers: Engineers{CertTTL: 8 * time.Hour},
		Attestation: Attestation{
			ChallengeTTL: 2 * time.Minute,
		},
	}
}

func (c *Config) check() error {
	var errs []error
	if _, ok := depots.Lookup(c.Depot.Site); !ok {
		errs = append(errs, fmt.Errorf("depot.site: unknown site code %q", c.Depot.Site))
	}
	if c.Depot.GatewayID == "" {
		errs = append(errs, errors.New("depot.gateway_id is required"))
	}
	if _, _, err := net.SplitHostPort(c.Listen.API); err != nil {
		errs = append(errs, fmt.Errorf("listen.api: %w", err))
	}
	for name, dir := range map[string]string{"state_dir": c.StateDir, "pki_dir": c.PKIDir} {
		if !filepath.IsAbs(dir) {
			errs = append(errs, fmt.Errorf("%s must be an absolute path, got %q", name, dir))
		}
	}
	if c.Tokens.TTL < time.Minute || c.Tokens.TTL > 7*24*time.Hour {
		errs = append(errs, fmt.Errorf("tokens.ttl must be between 1m and 168h, got %s", c.Tokens.TTL))
	}
	if err := httpsURL(c.Tokens.Issuer); err != nil {
		errs = append(errs, fmt.Errorf("tokens.issuer: %w", err))
	}
	if err := httpsURL(c.Upstream.URL); err != nil {
		errs = append(errs, fmt.Errorf("upstream.url: %w", err))
	}
	for i, ep := range c.Webhooks.Endpoints {
		if err := httpsURL(ep); err != nil {
			errs = append(errs, fmt.Errorf("webhooks.endpoints[%d]: %w", i, err))
		}
	}
	t := c.Telemetry
	if t.TopicBuckets < 1 || t.TopicBuckets > 256 {
		errs = append(errs, fmt.Errorf("telemetry.topic_buckets must be 1-256, got %d", t.TopicBuckets))
	}
	if t.Workers < 1 || t.Workers > 32 {
		errs = append(errs, fmt.Errorf("telemetry.workers must be 1-32, got %d", t.Workers))
	}
	if t.HashRingReplicas < 1 {
		errs = append(errs, fmt.Errorf("telemetry.hash_ring_replicas must be positive, got %d", t.HashRingReplicas))
	}
	if t.Archive.Every < time.Minute {
		errs = append(errs, fmt.Errorf("telemetry.archive.every must be at least 1m, got %s", t.Archive.Every))
	}
	if len(c.Engineers.Principals) == 0 {
		errs = append(errs, errors.New("engineers.principals: at least one principal is required"))
	}
	return errors.Join(errs...)
}

func httpsURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("want an https URL, got %q", s)
	}
	return nil
}

// StatePath returns the path of a file under state_dir.
func (c *Config) StatePath(name string) string {
	return filepath.Join(c.StateDir, name)
}

// PKIPath returns the path of a file under pki_dir.
func (c *Config) PKIPath(name string) string {
	return filepath.Join(c.PKIDir, name)
}
