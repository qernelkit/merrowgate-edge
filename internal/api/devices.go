package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Device is one depot device known to the gateway.
type Device struct {
	ID       string    `json:"id"`
	Model    string    `json:"model"`
	Dock     int       `json:"dock,omitempty"`
	Paired   time.Time `json:"paired"`
	LastSeen time.Time `json:"last_seen,omitzero"`
	// AttestKey is the DER public key of the device's TPM attestation key, recorded
	// when an engineer paired it. Label printers have no TPM and leave it empty.
	AttestKey []byte    `json:"attest_key,omitempty"`
	Attested  time.Time `json:"attested,omitzero"`
}

var errNoDevice = errors.New("api: unknown device")

// registry is the device list, kept as a JSON file under state_dir.
type registry struct {
	mu      sync.Mutex
	path    string
	devices map[string]*Device
}

func openRegistry(path string) (*registry, error) {
	r := &registry{path: path, devices: map[string]*Device{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, fmt.Errorf("api: devices: %w", err)
	}
	var list []*Device
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("api: devices: %s: %w", path, err)
	}
	for _, d := range list {
		r.devices[d.ID] = d
	}
	return r, nil
}

func (r *registry) get(id string) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return Device{}, errNoDevice
	}
	return *d, nil
}

func (r *registry) put(d Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[d.ID] = &d
	return r.saveLocked()
}

func (r *registry) update(id string, f func(*Device)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return errNoDevice
	}
	f(d)
	return r.saveLocked()
}

// page returns up to limit devices with IDs after `after`, in ID order.
func (r *registry) page(after string, limit int) (list []Device, more bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.devices))
	for id := range r.devices {
		if strings.Compare(id, after) > 0 {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	if len(ids) > limit {
		ids, more = ids[:limit], true
	}
	for _, id := range ids {
		list = append(list, *r.devices[id])
	}
	return list, more
}

func (r *registry) saveLocked() error {
	list := make([]*Device, 0, len(r.devices))
	for _, d := range r.devices {
		list = append(list, d)
	}
	slices.SortFunc(list, func(a, b *Device) int { return strings.Compare(a.ID, b.ID) })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("api: devices: %w", err)
	}
	tmp := r.path + ".new"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return fmt.Errorf("api: devices: %w", err)
	}
	return os.Rename(tmp, r.path)
}
