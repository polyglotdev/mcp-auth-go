package exchange_test

import (
	"testing"
	"time"

	"github.com/polyglotdev/mcp-auth-go/exchange"
)

func TestMemoryCacheFreshAndStale(t *testing.T) {
	now := time.Unix(1_000, 0)
	c := exchange.NewMemoryCache(func() time.Time { return now }, 30*time.Second)
	tok := &exchange.Token{AccessToken: "a", ExpiresAt: now.Add(2 * time.Minute)}
	c.Set("k", tok)

	if got, ok := c.Get("k"); !ok || got.AccessToken != "a" {
		t.Fatal("want fresh hit")
	}
	now = now.Add(90 * time.Second) // within 2m but past (2m - 30s leeway)? 90s < 90s? boundary
	now = now.Add(time.Second)      // now 91s in: ExpiresAt-leeway = 90s -> stale
	if _, ok := c.Get("k"); ok {
		t.Fatal("want stale miss after leeway boundary")
	}
}

func TestMemoryCacheIsolatesKeys(t *testing.T) {
	now := time.Unix(0, 0)
	c := exchange.NewMemoryCache(func() time.Time { return now }, 0)
	c.Set("user-1|aud|s", &exchange.Token{AccessToken: "one", ExpiresAt: now.Add(time.Hour)})
	if got, _ := c.Get("user-2|aud|s"); got != nil {
		t.Fatal("different key must not collide")
	}
}

// TestMemoryCacheGetDefensiveCopy verifies that mutating a Token returned by
// Get does not corrupt the stored entry (M1 review fix).
func TestMemoryCacheGetDefensiveCopy(t *testing.T) {
	now := time.Unix(0, 0)
	c := exchange.NewMemoryCache(func() time.Time { return now }, 0)
	original := &exchange.Token{
		AccessToken: "original",
		Scopes:      []string{"a", "b"},
		ExpiresAt:   now.Add(time.Hour),
	}
	c.Set("k", original)

	got, ok := c.Get("k")
	if !ok {
		t.Fatal("expected cache hit")
	}
	// Mutate the returned token.
	got.AccessToken = "mutated"
	got.Scopes[0] = "mutated-scope"

	// A second Get must still return the original values.
	got2, ok2 := c.Get("k")
	if !ok2 {
		t.Fatal("expected second cache hit")
	}
	if got2.AccessToken != "original" {
		t.Errorf("AccessToken = %q after mutation; want %q", got2.AccessToken, "original")
	}
	if got2.Scopes[0] != "a" {
		t.Errorf("Scopes[0] = %q after mutation; want %q", got2.Scopes[0], "a")
	}
}
