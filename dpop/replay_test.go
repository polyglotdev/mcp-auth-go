package dpop

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestMemoryReplayFirstSightThenReplay verifies that the first presentation of
// a (jti, htu) pair is accepted and the second is rejected as a replay. It
// also verifies that the same jti with a different htu is a distinct entry and
// is accepted -- jti uniqueness is per (jti, htu), not globally.
func TestMemoryReplayFirstSightThenReplay(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewMemoryReplayCache(func() time.Time { return now })
	exp := now.Add(60 * time.Second)
	if c.SeenBefore("jti1", "https://h/p", exp) {
		t.Fatal("first sight must be false")
	}
	if !c.SeenBefore("jti1", "https://h/p", exp) {
		t.Fatal("second sight (replay) must be true")
	}
	if c.SeenBefore("jti1", "https://other/p", exp) {
		t.Fatal("same jti, different htu must be allowed")
	}
}

// TestMemoryReplayExpiryResets verifies that an entry past its expiry is
// treated as unseen, allowing the same (jti, htu) pair to be re-used once the
// original proof has expired.
func TestMemoryReplayExpiryResets(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewMemoryReplayCache(func() time.Time { return now })
	exp := now.Add(30 * time.Second)
	c.SeenBefore("jti1", "u", exp)
	now = now.Add(31 * time.Second) // advance clock past exp
	if c.SeenBefore("jti1", "u", now.Add(30*time.Second)) {
		t.Fatal("expired entry must be treated as unseen")
	}
}

// TestMemoryReplayConcurrent exercises the contended mutex path and the inline
// sweep (replaySweepThreshold = 1024) under -race. 50 goroutines each write 22
// unique (jti, htu) pairs (50×22 = 1100 > 1024) while simultaneously hammering
// a single shared key, so both the contended and uncontended lock paths and the
// sweep branch are hit from multiple goroutines. The assertion is that the cache
// completes without panic and the race detector stays clean — no specific count
// is checked because correctness under concurrency is the entire point.
func TestMemoryReplayConcurrent(_ *testing.T) {
	const goroutines = 50
	const uniquePerGoroutine = 22 // 50×22 = 1100 > replaySweepThreshold

	c := NewMemoryReplayCache(nil)
	exp := time.Now().Add(time.Minute)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			// Hammer a shared key so many goroutines contend on the same map entry.
			c.SeenBefore("shared-jti", "https://example.com/shared", exp)

			// Write uniquePerGoroutine distinct keys to drive the map past the
			// sweep threshold and exercise the inline-sweep branch.
			for i := 0; i < uniquePerGoroutine; i++ {
				jti := fmt.Sprintf("g%d-jti%d", g, i)
				c.SeenBefore(jti, "https://example.com/resource", exp)
			}

			// Re-read the shared key to exercise the "already seen" return path
			// under concurrent load.
			c.SeenBefore("shared-jti", "https://example.com/shared", exp)
		}()
	}
	wg.Wait()
}

// TestNopReplayNeverSeen verifies that the no-op cache always returns false,
// effectively disabling replay protection while preserving the ReplayCache
// interface for callers that opt in to freshness-window-only protection.
func TestNopReplayNeverSeen(t *testing.T) {
	c := NewNopReplayCache()
	exp := time.Now().Add(time.Minute)
	if c.SeenBefore("a", "b", exp) {
		t.Fatal("nop cache first call must return false")
	}
	if c.SeenBefore("a", "b", exp) {
		t.Fatal("nop cache second call must return false (no replay)")
	}
}
