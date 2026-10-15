package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter allows each caller a burst of requests, refilled at one per interval.
type limiter struct {
	mu      sync.Mutex
	every   time.Duration
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(every time.Duration, burst int) *limiter {
	return &limiter{every: every, burst: float64(burst), buckets: make(map[string]*bucket)}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+float64(now.Sub(b.last))/float64(l.every))
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have been full for a while, so the map does not grow
// with every device that ever called.
func (l *limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
}

// rateLimit allows each caller 20 requests at once, refilled at one per second.
// Callers are keyed by the forwarded client address nginx sets.
func rateLimit(next http.Handler) http.Handler {
	tokens := newLimiter(time.Second, 20) // token bucket per device
	go func() {
		for now := range time.Tick(time.Minute) {
			tokens.sweep(now)
		}
	}()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokens.allow(clientAddr(r), time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientAddr is the address nginx saw: the last X-Forwarded-For entry, which nginx
// appends. Earlier entries come from the client and are not trusted.
func clientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
