package mcpauth_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
	"github.com/polyglotdev/mcp-auth-go/transport/mcpauth"
)

// okHandler returns a handler that writes 200, for asserting requests are let
// through.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// serveWithVerifier wraps a 200 handler with the SDK's RequireBearerToken using
// the given verifier, sends the bearer token, and returns the recorder.
func serveWithVerifier(t *testing.T, verify sdkauth.TokenVerifier, opts *sdkauth.RequireBearerTokenOptions, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	handler := sdkauth.RequireBearerToken(verify, opts)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// TestVerifierRejectsBadSignatureAs401 proves an invalid token is mapped to an
// error the SDK turns into 401 -- not the 500 it returns for any error that
// does not unwrap to its ErrInvalidToken sentinel.
func TestVerifierRejectsBadSignatureAs401(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	verify := mcpauth.NewTokenVerifier(v)

	token := j.MintWithWrongKey(t, jwkstest.ClaimSet{Subject: "alice"})

	rr := serveWithVerifier(t, verify, nil, token)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (a non-ErrInvalidToken error becomes 500)", rr.Code)
	}
}

// TestVerifierRejectsWrongAudienceAs401 proves the RFC 8707 audience check --
// the library's reason for existing, since the SDK performs none -- reaches the
// SDK as a 401: a token minted for a different resource is rejected.
func TestVerifierRejectsWrongAudienceAs401(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	verify := mcpauth.NewTokenVerifier(v)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject:  "alice",
		Audience: "https://some-other-resource.example.com",
	})

	rr := serveWithVerifier(t, verify, nil, token)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a token issued to the wrong audience", rr.Code)
	}
}

// TestErrorBodyCarriesPublicMessageWithoutCause proves the body the SDK writes
// is our safe, public message -- distinct per failure -- and never the wrapped
// validator cause (the SDK echoes err.Error() verbatim into the response).
func TestErrorBodyCarriesPublicMessageWithoutCause(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	verify := mcpauth.NewTokenVerifier(v)

	tests := []struct {
		name     string
		token    string
		wantBody string
	}{
		{
			name:     "invalid signature",
			token:    j.MintWithWrongKey(t, jwkstest.ClaimSet{Subject: "alice"}),
			wantBody: "could not be validated",
		},
		{
			name:     "expired",
			token:    j.Mint(t, jwkstest.ClaimSet{Subject: "alice", NotAfter: -time.Minute}),
			wantBody: "has expired",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := serveWithVerifier(t, verify, nil, tc.token)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rr.Code)
			}
			body := rr.Body.String()
			if !strings.Contains(body, tc.wantBody) {
				t.Errorf("body = %q, want it to contain %q", body, tc.wantBody)
			}
			if strings.Contains(body, "auth:") {
				t.Errorf("body = %q leaks the *auth.Error string form", body)
			}
		})
	}
}

// TestRequireBearerTokenInsufficientScope proves the convenience wirer routes
// required scopes through the SDK's own check: a validated token lacking a
// required scope gets 403 with an RFC 6750 scope challenge naming the scope.
func TestRequireBearerTokenInsufficientScope(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j) // no scope verifier; the SDK enforces Options.Scopes
	handler := mcpauth.RequireBearerToken(v, &mcpauth.Options{
		Scopes: []string{"mcp:write"},
	})(okHandler())

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{"scope": "mcp:read"}, // lacks mcp:write
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if wa := rr.Header().Get("WWW-Authenticate"); !strings.Contains(wa, `scope="mcp:write"`) {
		t.Errorf("challenge = %q, want scope=\"mcp:write\"", wa)
	}
}

// TestRequireBearerTokenHappyPathExposesTokenInfo proves a valid token reaches
// the protected handler and the mapped TokenInfo is readable from the request
// context via the SDK's accessor.
func TestRequireBearerTokenHappyPathExposesTokenInfo(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	var got *sdkauth.TokenInfo
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = sdkauth.TokenInfoFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := mcpauth.RequireBearerToken(v, nil)(next)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{"scope": "mcp:read"},
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body)
	}
	if got == nil {
		t.Fatal("handler saw no TokenInfo in context")
	}
	if got.UserID != "alice" {
		t.Errorf("UserID = %q, want alice", got.UserID)
	}
	if !slices.Contains(got.Scopes, "mcp:read") {
		t.Errorf("Scopes = %v, want to contain mcp:read", got.Scopes)
	}
}

// TestRequireBearerTokenChallengeCarriesResourceMetadata proves a 401 challenge
// carries the RFC 9728 resource_metadata pointer when configured.
func TestRequireBearerTokenChallengeCarriesResourceMetadata(t *testing.T) {
	const prm = "https://mcp.example.com/.well-known/oauth-protected-resource"
	j := jwkstest.New(t)
	v := newValidator(t, j)
	handler := mcpauth.RequireBearerToken(v, &mcpauth.Options{ResourceMetadataURL: prm})(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil) // no token -> 401
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if wa := rr.Header().Get("WWW-Authenticate"); !strings.Contains(wa, `resource_metadata="`+prm+`"`) {
		t.Errorf("challenge = %q, want resource_metadata pointer", wa)
	}
}

// TestNewTokenVerifierNilValidatorPanics proves a nil Validator is rejected at
// construction (fail fast) rather than nil-dereferencing on the first request.
func TestNewTokenVerifierNilValidatorPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewTokenVerifier(nil) should panic at construction")
		}
	}()
	_ = mcpauth.NewTokenVerifier(nil)
}
