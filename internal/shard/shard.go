// Package shard assigns devices to telemetry relay workers with a consistent hash
// ring, so adding a worker moves only about 1/n of the devices and each device's
// readings stay in order on one broker connection.
package shard

import (
	"fmt"
	"hash/fnv"
	"slices"
	"sort"
)

// Ring maps keys onto named nodes.
type Ring struct {
	replicas int
	points   []uint32
	owner    map[uint32]string
}

// NewRing returns an empty ring that places each node at replicas points.
func NewRing(replicas int) *Ring {
	return &Ring{replicas: max(replicas, 1), owner: make(map[uint32]string)}
}

// Add places a node on the ring.
func (r *Ring) Add(node string) {
	for i := range r.replicas {
		p := point(fmt.Sprintf("%s#%d", node, i))
		if _, taken := r.owner[p]; taken {
			continue
		}
		r.owner[p] = node
		r.points = append(r.points, p)
	}
	slices.Sort(r.points)
}

// Lookup returns the node that owns key, or "" when the ring is empty.
func (r *Ring) Lookup(key string) string {
	if len(r.points) == 0 {
		return ""
	}
	p := point(key)
	i := sort.Search(len(r.points), func(i int) bool { return r.points[i] >= p })
	if i == len(r.points) {
		i = 0
	}
	return r.owner[r.points[i]]
}

// point is a key's position on the ring.
func point(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return h.Sum32()
}
