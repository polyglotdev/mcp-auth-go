package exchange_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/exchange"
)

// ExampleExchanger_TokenForCaller shows the recommended pattern for exchanging
// the caller's inbound token for a downstream service token inside a tool
// handler. The ctx keys are populated by the auth middleware (HTTP transport)
// or mcpauth.ContextBridge() (MCP SDK transport).
func ExampleExchanger_TokenForCaller() {
	// NewExchanger and NewDPoP are called once at startup, not per-request.
	d, err := exchange.NewDPoP(exchange.BasicAuth{
		ClientID:     "svc-client-id",
		ClientSecret: "svc-client-secret",
	})
	if err != nil {
		panic(err)
	}
	ex, err := exchange.NewExchanger(exchange.Config{
		TokenURL:   "https://auth.example.com/oauth2/default/v1/token",
		ClientAuth: d,
	})
	if err != nil {
		panic(err)
	}

	// Inside a tool handler (net/http transport). On the MCP SDK transport,
	// wrap the method handler and install mcpauth.ContextBridge() so
	// auth.RawTokenFrom resolves from the SDK's TokenInfo.
	toolHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := ex.TokenForCaller(r.Context(), "api://downstream", "ds:read")
		if err != nil {
			http.Error(w, "exchange failed", http.StatusBadGateway)
			return
		}
		// tok.AccessToken is the downstream Bearer token for the service call.
		// It is a secret -- never log it.
		_ = tok
		w.WriteHeader(http.StatusOK)
	})
	_ = toolHandler

	// Fail-closed example: a context with no inbound token returns ErrMissingToken.
	_, err = ex.TokenForCaller(context.Background(), "api://downstream")
	if errors.Is(err, auth.ErrMissingToken) {
		fmt.Println("no caller token: fail closed")
	}
	// Output: no caller token: fail closed
}

// ExampleNewMemoryCache shows the per-process token cache the Exchanger uses by
// default. Entries are keyed by a caller-derived key (never the token bytes) and
// treated as stale a leeway before their ExpiresAt, so a token is refreshed
// before it actually expires. A nil clock uses time.Now; inject one for tests.
func ExampleNewMemoryCache() {
	now := time.Unix(1000, 0)
	cache := exchange.NewMemoryCache(func() time.Time { return now }, 30*time.Second)

	cache.Set("user-1|api://downstream|ds:read", &exchange.Token{
		AccessToken: "downstream-token",
		ExpiresAt:   now.Add(time.Hour),
	})

	if tok, ok := cache.Get("user-1|api://downstream|ds:read"); ok {
		fmt.Println("cache hit:", tok.AccessToken)
	}
	if _, ok := cache.Get("user-2|api://downstream|ds:read"); !ok {
		fmt.Println("different caller: miss")
	}

	// Output:
	// cache hit: downstream-token
	// different caller: miss
}
