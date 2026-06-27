package dpop_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
)

// ExampleNewVerifier shows how to create a DPoP verifier and attach it to
// MiddlewareConfig. The verifier enforces proof-of-possession for bound tokens
// and lets plain bearer tokens through (Opportunistic, the default).
//
// To mandate DPoP binding for every token, set Mode: dpop.Require.
// Behind a TLS-terminating proxy, set BaseURL to the public scheme+authority
// so the proof's htu matches (e.g. "https://mcp.example.com").
func ExampleNewVerifier() {
	// Create a DPoP verifier with default settings.
	// Opportunistic: only enforce on DPoP-bound tokens.
	_ = dpop.NewVerifier(dpop.Config{})

	// Require mode: reject any token that is not DPoP-bound.
	_ = dpop.NewVerifier(dpop.Config{Mode: dpop.Require})

	// Custom leeway (default is 60s):
	_ = dpop.NewVerifier(dpop.Config{IATLeeway: 30 * time.Second})

	// Disable replay protection (freshness window only):
	_ = dpop.NewVerifier(dpop.Config{ReplayCache: dpop.NewNopReplayCache()})
}

// TestNoTokenInErrorSurface asserts that a rejected proof's err.Error() string
// contains neither the access-token string nor its base64url SHA-256 preimage
// (the ath value). Every reject() in checkProof wraps a constant reason string,
// so the token value never appears in the error surface exposed to callers.
// The corresponding slog no-leak check lives in the transport layer
// (transport/http/middleware_test.go TestMiddlewareSlogNoTokenLeak) where
// writeAuthError actually emits log records.
func TestNoTokenInErrorSurface(t *testing.T) {
	now := time.Unix(2000, 0)
	k := newECKey(t)
	const accessToken = "super-secret-bearer-token-abc123"

	// --- bad ath (wrong token hash) ---
	proofBadAth := buildProof(t, k, map[string]any{
		"jti": "noleak-1",
		"htm": "POST",
		"htu": "https://mcp.example/tools/call",
		"iat": now.Unix(),
		"ath": athHash("wrong-token"), // deliberate mismatch
	})

	v := dpop.NewVerifier(dpop.Config{
		Now:         func() time.Time { return now },
		ReplayCache: dpop.NewNopReplayCache(),
	})
	in := dpop.Input{
		Proofs:      []string{proofBadAth},
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: accessToken,
		BoundJKT:    thumbprintOf(t, k),
	}
	err := v.Enforce(context.Background(), in)
	if err == nil {
		t.Fatal("expected rejection for bad ath, got nil")
	}
	if !isInvalidDPoP(err) {
		t.Fatalf("expected ErrInvalidDPoPProof, got %v", err)
	}

	errStr := err.Error()
	if strings.Contains(errStr, accessToken) {
		t.Errorf("err.Error() leaks the access token: %q", errStr)
	}
	if strings.Contains(errStr, athHash(accessToken)) {
		t.Errorf("err.Error() leaks the computed ath: %q", errStr)
	}

	// --- thumbprint mismatch (different key) ---
	k2 := newECKey(t)
	proofWrongKey := buildProof(t, k2, map[string]any{
		"jti": "noleak-2",
		"htm": "POST",
		"htu": "https://mcp.example/tools/call",
		"iat": now.Unix(),
		"ath": athHash(accessToken),
	})
	in2 := dpop.Input{
		Proofs:      []string{proofWrongKey},
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: accessToken,
		BoundJKT:    thumbprintOf(t, k), // different from k2
	}
	err2 := v.Enforce(context.Background(), in2)
	if err2 == nil {
		t.Fatal("expected rejection for thumbprint mismatch, got nil")
	}

	errStr2 := err2.Error()
	if strings.Contains(errStr2, accessToken) {
		t.Errorf("err.Error() (thumbprint mismatch) leaks the access token: %q", errStr2)
	}
	if strings.Contains(errStr2, thumbprintOf(t, k)) {
		t.Errorf("err.Error() (thumbprint mismatch) leaks the token jkt: %q", errStr2)
	}
}

// isInvalidDPoP reports whether err matches auth.ErrInvalidDPoPProof by code.
func isInvalidDPoP(err error) bool {
	return errors.Is(err, auth.ErrInvalidDPoPProof)
}
