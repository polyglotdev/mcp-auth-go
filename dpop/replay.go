package dpop

import (
	"sync"
	"time"
)

// ReplayCache records DPoP proof identifiers to enforce single-use (RFC 9449
// §11.1). Implementations MUST be safe for concurrent use.
type ReplayCache interface {
	// SeenBefore atomically records (jti, htu) with expiry exp and reports
	// whether that pair was already present and still unexpired (a replay).
	SeenBefore(jti, htu string, exp time.Time) bool
}

// replaySweepThreshold bounds the in-memory map: once it grows past this, a
// SeenBefore call sweeps expired entries inline (no background goroutine).
const replaySweepThreshold = 1024

// MemoryReplayCache is the in-memory default: a mutex-guarded map keyed
// "jti|htu", valued by each proof's expiry. Per-process only -- a
// multi-instance deployment behind a load balancer needs a shared ReplayCache
// for cross-instance single-use.
type MemoryReplayCache struct {
	mu   sync.Mutex
	now  func() time.Time
	seen map[string]time.Time
}

// NewMemoryReplayCache builds a MemoryReplayCache. now is injected for tests
// and defaults to time.Now when nil.
func NewMemoryReplayCache(now func() time.Time) *MemoryReplayCache {
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayCache{now: now, seen: map[string]time.Time{}}
}

// SeenBefore implements ReplayCache. It records (jti, htu) on first sight and
// returns false; on subsequent calls for the same pair within the expiry
// window it returns true (a replay). Expired entries are treated as unseen and
// overwritten. An inline sweep runs when the map exceeds replaySweepThreshold
// to keep memory bounded without a background goroutine.
func (c *MemoryReplayCache) SeenBefore(jti, htu string, exp time.Time) bool {
	key := jti + "|" + htu
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if prev, ok := c.seen[key]; ok && now.Before(prev) {
		return true // still within its window -- a replay
	}
	c.seen[key] = exp
	if len(c.seen) > replaySweepThreshold {
		for k, e := range c.seen {
			if !now.Before(e) { // expired
				delete(c.seen, k)
			}
		}
	}
	return false
}

// NewNopReplayCache returns a ReplayCache that records nothing and never
// reports a replay -- the explicit opt-out (freshness-window-only protection).
func NewNopReplayCache() ReplayCache { return nopReplayCache{} }

type nopReplayCache struct{}

func (nopReplayCache) SeenBefore(_, _ string, _ time.Time) bool { return false }
