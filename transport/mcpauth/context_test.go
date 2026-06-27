package mcpauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
	"github.com/polyglotdev/mcp-auth-go/transport/mcpauth"
)

func TestContextBridgePopulatesCoreKeysFromTokenInfo(t *testing.T) {
	// A valid bearer through RequireBearerToken puts a TokenInfo (carrying our
	// stashed claims + raw token in Extra, but NO core keys) on r.Context().
	// Inside that handler we invoke the ContextBridge-wrapped method handler with
	// r.Context() and assert it copied both into the CORE keys -- a passing test
	// proves the Extra->core-key copy, not a no-op.
	j := jwkstest.New(t)
	v := newValidator(t, j)
	tok := j.Mint(t, jwkstest.ClaimSet{Subject: "user-1"})

	var sawClaims bool
	var sawRaw string
	bridged := mcpauth.ContextBridge()(func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
		_, sawClaims = auth.ClaimsFrom(ctx)
		sawRaw, _ = auth.RawTokenFrom(ctx)
		return &mcp.CallToolResult{}, nil // non-nil result honors the MethodHandler contract
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := bridged(r.Context(), "tools/call", nil); err != nil {
			t.Errorf("bridged handler: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})
	h := mcpauth.RequireBearerToken(v, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !sawClaims || sawRaw != tok {
		t.Fatalf("bridge did not copy from TokenInfo.Extra: claims=%v raw=%q want raw=%q", sawClaims, sawRaw, tok)
	}
}
