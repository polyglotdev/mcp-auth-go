package auth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// tokenWith builds an unsigned jwt.Token carrying claims. The verifier only
// reads claims, so signing is unnecessary here.
func tokenWith(t *testing.T, claims map[string]any) jwt.Token {
	t.Helper()
	b := jwt.NewBuilder()
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	return tok
}

// assertForbidden asserts err is the authorization sentinel mapping to 403.
func assertForbidden(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	var e *auth.Error
	if !errors.As(err, &e) || e.HTTPStatus != http.StatusForbidden {
		t.Errorf("expected 403 *auth.Error, got %v", err)
	}
}

// TestVerifyRequiredStringClaims proves a present, matching string claim passes,
// a missing required claim is rejected as ErrForbidden (403 -- an authorization
// failure, not an authentication one), and an empty requirement map is a no-op.
func TestVerifyRequiredStringClaims(t *testing.T) {
	tests := []struct {
		name          string
		required      map[string]string
		claims        map[string]any
		wantForbidden bool
	}{
		{name: "present and matching passes", required: map[string]string{"tier": "internal"}, claims: map[string]any{"tier": "internal"}},
		{name: "missing required claim is forbidden", required: map[string]string{"tier": "internal"}, claims: map[string]any{"sub": "alice"}, wantForbidden: true},
		{name: "empty requirements is a no-op", required: map[string]string{}, claims: map[string]any{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := auth.VerifyRequiredStringClaims(tc.required)
			err := v(context.Background(), tokenWith(t, tc.claims))
			if tc.wantForbidden {
				assertForbidden(t, err)
				return
			}
			if err != nil {
				t.Errorf("verify = %v, want nil", err)
			}
		})
	}
}

// TestVerifyRequiredStringClaimsWrong exercises every shape of "claim present
// but not the value we require" -- wrong string, wrong type, empty. Each must
// surface as ErrForbidden so a transport adapter maps it to 403.
func TestVerifyRequiredStringClaimsWrong(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "different string", value: "external"},
		{name: "case-sensitive mismatch", value: "INTERNAL"},
		{name: "empty string", value: ""},
		{name: "wrong type int", value: 123},
		{name: "wrong type bool", value: true},
		{name: "wrong type float", value: 1.5},
	}

	v := auth.VerifyRequiredStringClaims(map[string]string{"tier": "internal"})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := tokenWith(t, map[string]any{"tier": tc.value})
			assertForbidden(t, v(context.Background(), tok))
		})
	}
}

// TestVerifyRequiredStringClaimsMultiple proves all required claims must match
// when more than one is specified, and that a single missing one fails.
func TestVerifyRequiredStringClaimsMultiple(t *testing.T) {
	v := auth.VerifyRequiredStringClaims(map[string]string{
		"tier":    "internal",
		"backend": "bedrock",
	})

	ok := tokenWith(t, map[string]any{"tier": "internal", "backend": "bedrock"})
	if err := v(context.Background(), ok); err != nil {
		t.Errorf("all-present verify = %v, want nil", err)
	}

	missing := tokenWith(t, map[string]any{"tier": "internal"})
	assertForbidden(t, v(context.Background(), missing))
}

// assertInsufficientScope asserts err is the insufficient-scope sentinel,
// distinct from a generic forbidden, mapping to 403.
func assertInsufficientScope(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, auth.ErrInsufficientScope) {
		t.Fatalf("err = %v, want ErrInsufficientScope", err)
	}
	var e *auth.Error
	if !errors.As(err, &e) || e.HTTPStatus != http.StatusForbidden {
		t.Errorf("expected 403 *auth.Error, got %v", err)
	}
}

// TestRequireScopes proves a token carrying all required scopes passes (whether
// the scopes arrive as the space-delimited "scope" string or the array "scp"
// claim), a missing scope yields ErrInsufficientScope (403, distinct from the
// generic ErrForbidden), and requiring no scopes is a no-op.
func TestRequireScopes(t *testing.T) {
	tests := []struct {
		name                  string
		required              []string
		claims                map[string]any
		wantInsufficientScope bool
	}{
		{name: "all present via scope string", required: []string{"mcp:read"}, claims: map[string]any{"scope": "mcp:read mcp:write"}},
		{name: "missing scope", required: []string{"mcp:write"}, claims: map[string]any{"scope": "mcp:read"}, wantInsufficientScope: true},
		{name: "accepts scp array", required: []string{"mcp:read", "mcp:write"}, claims: map[string]any{"scp": []any{"mcp:read", "mcp:write"}}},
		{name: "empty requirement is a no-op", required: nil, claims: map[string]any{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := auth.RequireScopes(tc.required...)
			err := v(context.Background(), tokenWith(t, tc.claims))
			if tc.wantInsufficientScope {
				assertInsufficientScope(t, err)
				return
			}
			if err != nil {
				t.Errorf("verify = %v, want nil", err)
			}
		})
	}
}
