package exchange

import (
	"sync"
	"time"
)

// Cache stores exchanged tokens. Get returns a usable token for key, or
// (nil,false) if absent or no longer fresh. Implementations MUST be safe for
// concurrent use. The returned *Token is owned by the caller: mutating it must
// not affect subsequent Get calls. Values are secrets.
type Cache interface {
	Get(key string) (*Token, bool)
	Set(key string, tok *Token)
}

// MemoryCache is the in-memory default: a mutex-guarded map that drops an entry
// once now() >= ExpiresAt - leeway.
type MemoryCache struct {
	mu     sync.Mutex
	now    func() time.Time
	leeway time.Duration
	items  map[string]*Token
}

// NewMemoryCache builds a MemoryCache. now defaults to time.Now if nil; leeway
// is the safety margin subtracted from each entry's ExpiresAt.
func NewMemoryCache(now func() time.Time, leeway time.Duration) *MemoryCache {
	if now == nil {
		now = time.Now
	}
	return &MemoryCache{now: now, leeway: leeway, items: map[string]*Token{}}
}

// Get returns a copy of the cached token for key, or (nil, false) if absent or
// stale. The returned *Token is a defensive copy owned by the caller: mutating
// it does not affect the stored entry.
func (c *MemoryCache) Get(key string) (*Token, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tok, ok := c.items[key]
	if !ok {
		return nil, false
	}
	if !c.now().Before(tok.ExpiresAt.Add(-c.leeway)) { // now >= ExpiresAt - leeway => stale
		delete(c.items, key)
		return nil, false
	}
	// Return a copy so a caller mutating the Token struct or its Scopes slice
	// cannot corrupt the shared cache entry.
	cp := *tok
	if tok.Scopes != nil {
		cp.Scopes = append([]string(nil), tok.Scopes...)
	}
	return &cp, true
}

// Set stores tok under key, replacing any existing entry.
func (c *MemoryCache) Set(key string, tok *Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = tok
}
