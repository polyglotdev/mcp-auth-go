package introspection

import (
	"sync"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// Cache stores introspection results keyed by an opaque, non-reversible token
// digest (the Validator keys on base64url(sha256(token)), never the raw token).
// Get returns a usable *auth.Claims for key, or (nil, false) if absent or no
// longer fresh. Implementations MUST be safe for concurrent use, and MUST NOT
// let a caller mutating a returned *auth.Claims (or the value passed to Set)
// corrupt a stored entry -- both boundaries must deep-copy. A cached *auth.Claims
// is an authorization verdict; treat it as sensitive.
type Cache interface {
	Get(key string) (*auth.Claims, bool)
	Set(key string, claims *auth.Claims)
}

// MemoryCache is the in-memory default: a mutex-guarded map that drops an entry
// once now() >= ExpiresAt - leeway. It deep-copies on both Set and Get so a
// caller cannot corrupt a stored entry through a shared slice or the Raw map.
type MemoryCache struct {
	mu     sync.Mutex
	now    func() time.Time
	leeway time.Duration
	items  map[string]*auth.Claims
}

// NewMemoryCache builds a MemoryCache. now defaults to time.Now if nil; leeway
// is the safety margin subtracted from each entry's ExpiresAt before it is
// considered stale.
func NewMemoryCache(now func() time.Time, leeway time.Duration) *MemoryCache {
	if now == nil {
		now = time.Now
	}
	return &MemoryCache{now: now, leeway: leeway, items: map[string]*auth.Claims{}}
}

// Set stores a deep copy of claims under key, replacing any existing entry. The
// copy isolates the stored entry from later mutation of the caller's *Claims
// (which Validate also returns to the caller).
func (c *MemoryCache) Set(key string, claims *auth.Claims) {
	cp := copyClaims(claims)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = cp
}

// Get returns a deep copy of the cached claims for key, or (nil, false) if
// absent or stale. The copy isolates the stored entry from caller mutation.
func (c *MemoryCache) Get(key string) (*auth.Claims, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	claims, ok := c.items[key]
	if !ok {
		return nil, false
	}
	if !c.now().Before(claims.ExpiresAt.Add(-c.leeway)) { // now >= ExpiresAt - leeway => stale
		delete(c.items, key)
		return nil, false
	}
	return copyClaims(claims), true
}

// copyClaims returns a deep copy of claims: fresh Audience/Scopes slices and a
// fresh Raw map, so mutation of one copy cannot corrupt another. A shallow copy
// would share the Raw map and let one request's handler corrupt another's
// cached claims.
func copyClaims(c *auth.Claims) *auth.Claims {
	cp := *c
	if c.Audience != nil {
		cp.Audience = append([]string(nil), c.Audience...)
	}
	if c.Scopes != nil {
		cp.Scopes = append([]string(nil), c.Scopes...)
	}
	if c.Raw != nil {
		cp.Raw = make(map[string]string, len(c.Raw))
		for k, v := range c.Raw {
			cp.Raw[k] = v
		}
	}
	return &cp
}
