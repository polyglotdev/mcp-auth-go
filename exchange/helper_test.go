package exchange_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/exchange"
)

func TestTokenForCallerFailsClosed(t *testing.T) {
	// A context with no raw token must return ErrMissingToken and must not
	// call the AS at all.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ex.TokenForCaller(context.Background(), "aud")
	if !errors.Is(err, auth.ErrMissingToken) {
		t.Fatalf("want ErrMissingToken, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("AS called %d times; want 0 (fail closed with no caller token)", calls)
	}
}

func TestTokenForCallerSucceedsWithRawToken(t *testing.T) {
	// A context carrying a raw token and claims drives a real exchange.
	srv, asCalls := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"downstream","token_type":"Bearer","expires_in":3600}`))
	})

	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	if err != nil {
		t.Fatal(err)
	}

	claims := &auth.Claims{Subject: "user-1"}
	ctx := auth.WithRawToken(auth.WithClaims(context.Background(), claims), "raw-inbound-token")

	tok, err := ex.TokenForCaller(ctx, "aud")
	if err != nil {
		t.Fatalf("TokenForCaller: %v", err)
	}
	if tok.AccessToken != "downstream" {
		t.Fatalf("token = %+v", tok)
	}
	if *asCalls != 1 {
		t.Fatalf("AS called %d times; want 1", *asCalls)
	}
}

func TestTokenForCallerCachesOnSubject(t *testing.T) {
	// Two calls with the same ctx (same raw token + subject) hit the AS once.
	srv, asCalls := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"downstream","token_type":"Bearer","expires_in":3600}`))
	})

	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	if err != nil {
		t.Fatal(err)
	}

	claims := &auth.Claims{Subject: "user-cache"}
	ctx := auth.WithRawToken(auth.WithClaims(context.Background(), claims), "raw-inbound-token")

	if _, err := ex.TokenForCaller(ctx, "aud"); err != nil {
		t.Fatal(err)
	}
	if _, err := ex.TokenForCaller(ctx, "aud"); err != nil {
		t.Fatal(err)
	}
	if *asCalls != 1 {
		t.Fatalf("AS called %d times; want 1 (cache hit on second call)", *asCalls)
	}
}
