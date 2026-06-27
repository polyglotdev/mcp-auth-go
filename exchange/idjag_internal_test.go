package exchange

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCacheKeyTokenTypes guards against an ID-JAG mint and a plain access-token
// exchange for the same caller sharing a cache entry.
func TestCacheKeyTokenTypes(t *testing.T) {
	scope := []string{"chat.read"}
	plain := cacheKey("sub", "aud", "", "", scope)
	idjag := cacheKey("sub", "aud", TokenTypeIDToken, TokenTypeIDJAG, scope)
	if plain == idjag {
		t.Fatalf("cacheKey collision: plain and id-jag share key %q", plain)
	}
}

// TestProvideCacheKeyNoTokenBytes proves the final-token cache key is derived
// from the explicit Subject, never from the SubjectAssertion bytes.
func TestProvideCacheKeyNoTokenBytes(t *testing.T) {
	const assertion = "SUBJECT-ASSERTION-DISTINCTIVE-marker"
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"idjag","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag","token_type":"N_A","expires_in":300}`))
	}))
	defer idpSrv.Close()
	rasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"down","token_type":"Bearer","expires_in":3600}`))
	}))
	defer rasSrv.Close()

	now := time.Unix(1000, 0)
	mc := NewMemoryCache(func() time.Time { return now }, 30*time.Second)
	p, err := NewDownstreamProvider(DownstreamConfig{
		IDP:        Endpoint{TokenURL: idpSrv.URL, ClientAuth: BasicAuth{}},
		ResourceAS: Endpoint{TokenURL: rasSrv.URL, ClientAuth: BasicAuth{}},
		Audience:   "aud",
		Cache:      mc,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Provide(context.Background(), ProvideRequest{SubjectAssertion: assertion, Subject: "user-1"}); err != nil {
		t.Fatal(err)
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()
	if len(mc.items) == 0 {
		t.Fatal("expected a cached entry")
	}
	for key := range mc.items {
		if strings.Contains(key, assertion) {
			t.Fatalf("cache key contains assertion bytes: %q", key)
		}
	}
}
