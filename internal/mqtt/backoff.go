package mqtt

import (
	"math/rand/v2"
	"time"
)

// backoff spaces out reconnect attempts to the broker: 1s, 2s, 4s and so on up to a
// minute, plus up to a quarter more at random so the workers do not all reconnect
// in step after a broker restart.
type backoff struct {
	failures int
	until    time.Time
}

func (b *backoff) ready(now time.Time) bool {
	return !now.Before(b.until)
}

func (b *backoff) failed(now time.Time) {
	b.failures++
	d := min(time.Second<<min(b.failures-1, 6), time.Minute)
	b.until = now.Add(d + rand.N(d/4+1))
}

func (b *backoff) reset() {
	b.failures = 0
	b.until = time.Time{}
}
