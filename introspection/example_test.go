package introspection_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/introspection"
)

// Example shows validating an opaque bearer token via an RFC 7662 introspection
// endpoint. The resource server confirms the issuer and audience itself (an
// active token minted for another resource must not be accepted), and returns
// typed *auth.Claims. The endpoint must be https; loopback http is allowed for a
// same-host sidecar and for tests like this one.
func Example() {
	const (
		issuer   = "https://issuer.example.com"
		audience = "https://mcp.internal.example.com"
	)

	// Stand in for the authorization server's RFC 7662 endpoint.
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"active":true,"sub":"alice","iss":%q,"aud":%q,"scope":"mcp:read"}`, issuer, audience)
	}))
	defer as.Close()

	v, err := introspection.NewValidator(introspection.Config{
		IntrospectionURL: as.URL, // production must be https; loopback http is allowed
		ClientAuth:       introspection.BasicAuth{ClientID: "rs", ClientSecret: "rs-secret"},
		Issuer:           issuer,
		Audience:         audience,
	})
	if err != nil {
		panic(err) // panic (not log.Fatal) so the deferred as.Close() still runs
	}

	claims, err := v.Validate(context.Background(), "opaque-access-token")
	if err != nil {
		panic(err)
	}
	fmt.Println("subject:", claims.Subject)
	fmt.Println("scopes:", claims.Scopes)

	// Output:
	// subject: alice
	// scopes: [mcp:read]
}

// ExampleNewMemoryCache shows the optional result cache. With caching off (the
// default) every Validate hits the authorization server, so a revoked token is
// rejected immediately; enable a cache to trade that immediacy for fewer calls.
// Entries are bounded by the response exp minus a leeway and keyed by an opaque
// token digest, never the raw token.
func ExampleNewMemoryCache() {
	now := time.Unix(1000, 0)
	cache := introspection.NewMemoryCache(func() time.Time { return now }, 30*time.Second)

	cache.Set("token-digest", &auth.Claims{
		Subject:   "alice",
		ExpiresAt: now.Add(time.Hour),
	})

	if claims, ok := cache.Get("token-digest"); ok {
		fmt.Println("cache hit:", claims.Subject)
	}
	if _, ok := cache.Get("unknown-digest"); !ok {
		fmt.Println("unknown token: miss")
	}

	// Output:
	// cache hit: alice
	// unknown token: miss
}

// ExampleBasicAuth shows authenticating the resource server to the introspection
// endpoint with HTTP Basic credentials (RFC 7617) in the Authorization header.
func ExampleBasicAuth() {
	req := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/introspect", nil)

	ca := introspection.BasicAuth{ClientID: "rs", ClientSecret: "rs-secret"}
	if err := ca.Apply(req, nil); err != nil {
		log.Fatal(err)
	}

	id, _, ok := req.BasicAuth()
	fmt.Println("has basic auth:", ok)
	fmt.Println("client id:", id)

	// Output:
	// has basic auth: true
	// client id: rs
}

// ExampleFormPost shows the alternative client authentication: credentials in
// the POST body rather than the Authorization header, for authorization servers
// that require it.
func ExampleFormPost() {
	form := url.Values{}

	ca := introspection.FormPost{ClientID: "rs", ClientSecret: "rs-secret"}
	if err := ca.Apply(nil, form); err != nil {
		log.Fatal(err)
	}

	fmt.Println("client_id:", form.Get("client_id"))

	// Output: client_id: rs
}
