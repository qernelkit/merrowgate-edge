// Package audit keeps the gateway's append-only audit log: sign-ins, pairings,
// firmware decisions and bastion access. Each record carries the hash of the one
// before it, so a removed or edited line breaks the chain from that point on, and
// `edgectl audit-check` reports where.
package audit

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Record is one line of the log.
type Record struct {
	Seq    uint64    `json:"seq"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Prev   string    `json:"prev"`
	Hash   string    `json:"hash"`
}

// Log appends records to a file.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	seq  uint64
	last string
}

// Open opens the log at path, checking the existing chain and continuing it.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	seq, last, err := Check(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %s: %w", path, err)
	}
	return &Log{f: f, seq: seq, last: last}, nil
}

// Append writes one record.
func (l *Log) Append(actor, action, target string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := Record{Seq: l.seq + 1, At: time.Now().UTC(), Actor: actor, Action: action, Target: target, Prev: l.last}
	h, err := link(r)
	if err != nil {
		return err
	}
	r.Hash = h
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	l.seq, l.last = r.Seq, r.Hash
	return nil
}

// Close closes the log file.
func (l *Log) Close() error {
	return l.f.Close()
}

// ErrBroken reports the first record whose chain does not hold.
type ErrBroken struct{ Seq uint64 }

func (e ErrBroken) Error() string { return fmt.Sprintf("chain breaks at record %d", e.Seq) }

// Check reads a log from the start and returns the last sequence number and hash.
func Check(r io.Reader) (uint64, string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var seq uint64
	var last string
	for sc.Scan() {
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return seq, last, ErrBroken{Seq: seq + 1}
		}
		h, err := link(rec)
		if err != nil {
			return seq, last, err
		}
		if rec.Seq != seq+1 || rec.Prev != last || rec.Hash != h {
			return seq, last, ErrBroken{Seq: seq + 1}
		}
		seq, last = rec.Seq, rec.Hash
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return seq, last, err
	}
	return seq, last, nil
}

// link is the record's hash: over the previous hash and the record without its own.
func link(r Record) (string, error) {
	r.Hash = ""
	body, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("audit: %w", err)
	}
	h := sha512.New()
	h.Write([]byte(r.Prev))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}
