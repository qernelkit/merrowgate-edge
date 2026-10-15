// Package mqtt relays device telemetry to the depot's MQTT broker. Devices post
// sealed readings to the control API; the relay opens each one with the device's
// session key and republishes the reading for depot consumers (dock displays, the
// yard system) on depots/<site>/telemetry/<bucket>/<device>.
package mqtt

import (
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"sync"
	"time"

	"merrowgate.example/edge/internal/config"
	"merrowgate.example/edge/internal/shard"
)

// MaxReading is the largest reading a device may send in one envelope.
const MaxReading = 64 << 10

// ErrNoSession means the device has not opened a session since the gateway started.
var ErrNoSession = errors.New("mqtt: device has no open session")

// Relay opens telemetry envelopes and publishes the readings.
type Relay struct {
	site     string
	bucketOf func(deviceID string) uint32
	ring     *shard.Ring
	workers  map[string]*publisher
	archive  *archiver

	mu        sync.RWMutex
	envelopes map[string]*Envelope
}

// NewRelay checks the telemetry section of gateway.yaml and prepares one broker
// connection per worker. Devices are spread over topic_buckets topics by a checksum
// of their ID, so one busy scanner cannot hold up a whole depot's consumers.
func NewRelay(site, gatewayID string, cfg config.Telemetry, password string, store ArchiveStore) (*Relay, error) {
	buckets := uint32(cfg.TopicBuckets)
	if cfg.Envelope != "chacha20-poly1305" {
		return nil, fmt.Errorf("telemetry: unsupported scheme %q", cfg.Envelope)
	}
	bucketOf := func(deviceID string) uint32 { return crc32.ChecksumIEEE([]byte(deviceID)) % buckets }
	r := &Relay{
		site:      strings.ToLower(site),
		bucketOf:  bucketOf,
		ring:      shard.NewRing(cfg.HashRingReplicas),
		workers:   make(map[string]*publisher, cfg.Workers),
		envelopes: make(map[string]*Envelope),
	}
	for i := range cfg.Workers {
		name := fmt.Sprintf("%s-relay-%d", gatewayID, i)
		r.ring.Add(name)
		r.workers[name] = &publisher{addr: cfg.Broker, clientID: name, user: cfg.Username, password: password}
	}
	if store != nil {
		r.archive = newArchiver(store, cfg.Archive, r.site)
	}
	return r, nil
}

// SetSessionKey installs the envelope for a device's new session.
func (r *Relay) SetSessionKey(deviceID string, key []byte) error {
	env, err := NewEnvelope(key)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.envelopes[deviceID] = env
	r.mu.Unlock()
	return nil
}

// Forward opens a sealed reading from deviceID and publishes it.
func (r *Relay) Forward(deviceID string, sealed []byte) error {
	r.mu.RLock()
	env, ok := r.envelopes[deviceID]
	r.mu.RUnlock()
	if !ok {
		return ErrNoSession
	}
	reading, err := env.Open(deviceID, sealed)
	if err != nil {
		return err
	}
	if len(reading) > MaxReading {
		return fmt.Errorf("mqtt: reading from %s is %d bytes, limit %d", deviceID, len(reading), MaxReading)
	}
	topic := r.Topic(deviceID)
	w := r.workers[r.ring.Lookup(deviceID)]
	if err := w.publish(topic, reading); err != nil {
		return err
	}
	if r.archive != nil {
		r.archive.add(time.Now(), deviceID, reading)
	}
	return nil
}

// Topic is the broker topic for a device's readings.
func (r *Relay) Topic(deviceID string) string {
	return fmt.Sprintf("depots/%s/telemetry/%02d/%s", r.site, r.bucketOf(deviceID), deviceID)
}

// Run flushes archives until stop is closed, then closes the broker connections.
func (r *Relay) Run(stop <-chan struct{}) {
	if r.archive != nil {
		r.archive.run(stop)
	} else {
		<-stop
	}
	for _, w := range r.workers {
		w.close()
	}
}
