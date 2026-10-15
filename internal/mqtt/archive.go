package mqtt

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"path"
	"sync"
	"time"

	"merrowgate.example/edge/internal/config"
)

// ArchiveStore takes finished telemetry archives; the cloud upstream client is one.
type ArchiveStore interface {
	Put(ctx context.Context, path, contentType string, body []byte) error
}

// archiver batches readings into JSON Lines files and uploads one per period to
// <bucket>/<key_prefix><site>/<yyyy>/<mm>/<dd>/<hhmm>.jsonl.
type archiver struct {
	store  ArchiveStore
	bucket string
	prefix string
	site   string
	every  time.Duration

	mu    sync.Mutex
	buf   bytes.Buffer
	start time.Time
}

func newArchiver(store ArchiveStore, cfg config.Archive, site string) *archiver {
	return &archiver{store: store, bucket: cfg.Bucket, prefix: cfg.KeyPrefix, site: site, every: cfg.Every}
}

func (a *archiver) add(now time.Time, deviceID string, reading []byte) {
	line, err := json.Marshal(struct {
		At      time.Time       `json:"at"`
		Device  string          `json:"device"`
		Reading json.RawMessage `json:"reading"`
	}{now.UTC(), deviceID, json.RawMessage(reading)})
	if err != nil {
		return // not JSON; the broker copy is all there is
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.buf.Len() == 0 {
		a.start = now.UTC()
	}
	a.buf.Write(line)
	a.buf.WriteByte('\n')
}

func (a *archiver) run(stop <-chan struct{}) {
	t := time.NewTicker(a.every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.flush()
		case <-stop:
			a.flush()
			return
		}
	}
}

func (a *archiver) flush() {
	a.mu.Lock()
	if a.buf.Len() == 0 {
		a.mu.Unlock()
		return
	}
	body := bytes.Clone(a.buf.Bytes())
	start := a.start
	a.buf.Reset()
	a.mu.Unlock()

	key := path.Join(a.bucket, a.prefix+a.site, start.Format("2006/01/02/1504")+".jsonl")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := a.store.Put(ctx, "/v1/archive/"+key, "application/x-ndjson", body); err != nil {
		log.Printf("telemetry archive %s (%d bytes) not uploaded: %v", key, len(body), err)
	}
}
