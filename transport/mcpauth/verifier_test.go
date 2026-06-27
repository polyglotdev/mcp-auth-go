package mcpauth_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
	"github.com/polyglotdev/mcp-auth-go/transport/mcpauth"
)

// newValidator builds a Validator pointed at the test JWKS, with optional
// authorization verifiers.
func newValidator(t *testing.T, j *jwkstest.JWKS, verifiers ...auth.ClaimVerifier) *auth.Validator {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:   j.URL(),
		Issuer:    j.Issuer(),
		Audience:  j.Audience(),
		Verifiers: verifiers,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func TestRawTokenFromContextReadsStashedToken(t *testing.T) {
	// The SDK has no public writer for TokenInfo on a context (the only writer is
	// private, inside RequireBearerToken). So drive a real validated token through
	// the bearer middleware: the SDK then places a TokenInfo carrying our stashed
	// raw token (in Extra) on r.Context(), and RawTokenFromContext recovers it.
	// Reuse this package's existing jwkstest/newValidator harness.
	j := jwkstest.New(t)
	v := newValidator(t, j)
	tok := j.Mint(t, jwkstest.ClaimSet{Subject: "user-1"})

	var seen string
	var seenOK bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, seenOK = mcpauth.RawTokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := mcpauth.RequireBearerToken(v, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !seenOK || seen != tok {
		t.Fatalf("RawTokenFromContext = %q, %v; want the minted token, true", seen, seenOK)
	}
}

// TestRequireBearerTokenEnforcesDPoP proves a bound token (cnf.jkt) presented
// without a DPoP header results in 401 when Options.DPoP is configured.
func TestRequireBearerTokenEnforcesDPoP(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	dv := dpop.NewVerifier(dpop.Config{})

	boundTok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "u",
		Private: map[string]any{"cnf": map[string]any{"jkt": "deadbeef"}},
	})

	h := mcpauth.RequireBearerToken(v, &mcpauth.Options{DPoP: dv})(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+boundTok)
	// Deliberately no DPoP header.
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (bound token, no proof)", rec.Code)
	}
}

// TestRequireBearerTokenDPoPHappyPath proves a bound token paired with a valid
// DPoP proof passes through RequireBearerToken and the inner handler runs (200).
// This is the accept-path complement to TestRequireBearerTokenEnforcesDPoP.
func TestRequireBearerTokenDPoPHappyPath(t *testing.T) {
	j := jwkstest.New(t)

	// Generate an ES256 key for the DPoP proof.
	rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, err := jwk.FromRaw(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = dpopKey.Set(jwk.AlgorithmKey, jwa.ES256)

	// Compute the JWK thumbprint of the public key for cnf.jkt.
	pubKey, _ := dpopKey.PublicKey()
	tp, err := pubKey.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(tp)

	// Mint a token that is bound to the DPoP key via cnf.jkt.
	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{"cnf": map[string]any{"jkt": jkt}},
	})

	// Build the DPoP proof. Use BaseURL so we control the htu value exactly.
	const baseURL = "https://mcp.example.com"
	const method = http.MethodPost
	const path = "/mcp"
	htu := baseURL + path

	ath := func() string {
		sum := sha256.Sum256([]byte(tok))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}()

	proofPayload, _ := json.Marshal(map[string]any{
		"jti": "happy-path-id",
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
		"ath": ath,
	})
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.TypeKey, "dpop+jwt")
	_ = hdr.Set(jws.JWKKey, pubKey)
	signed, err := jws.Sign(proofPayload, jws.WithKey(jwa.ES256, dpopKey, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	proof := string(signed)

	v := newValidator(t, j)
	dv := dpop.NewVerifier(dpop.Config{ReplayCache: dpop.NewNopReplayCache()})

	var handlerRan bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusOK)
	})
	h := mcpauth.RequireBearerToken(v, &mcpauth.Options{
		DPoP:    dv,
		BaseURL: baseURL,
	})(inner)

	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (valid bound token + proof); body: %s", rec.Code, rec.Body)
	}
	if !handlerRan {
		t.Fatal("inner handler did not run; request was rejected when it should have passed")
	}
}

// TestNewTokenVerifierMapsValidToken proves a valid token is mapped into the
// SDK's TokenInfo: Subject->UserID, the granted scopes, and a non-zero
// Expiration (which the SDK itself re-checks).
func TestNewTokenVerifierMapsValidToken(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	verify := mcpauth.NewTokenVerifier(v)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{"scope": "mcp:read mcp:write"},
	})

	info, err := verify(context.Background(), token, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if info == nil {
		t.Fatal("verify returned nil TokenInfo")
	}
	if info.UserID != "alice" {
		t.Errorf("UserID = %q, want alice", info.UserID)
	}
	if want := []string{"mcp:read", "mcp:write"}; !slices.Equal(info.Scopes, want) {
		t.Errorf("Scopes = %v, want %v", info.Scopes, want)
	}
	if info.Expiration.IsZero() {
		t.Error("Expiration is zero; the SDK requires a non-zero expiration")
	}
}

// TestRequireBearerTokenNonceVerifierConstructs proves a nonce-configured
// dpop.Verifier no longer panics on the SDK transport (slice #3): it constructs,
// and serves the DPoP nonce challenge via the response wrapper.
func TestRequireBearerTokenNonceVerifierConstructs(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	ns, err := dpop.NewSignedNonce(make([]byte, 32), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	if h := mcpauth.RequireBearerToken(v, &mcpauth.Options{DPoP: dpop.NewVerifier(dpop.Config{Nonce: ns})}); h == nil {
		t.Fatal("RequireBearerToken returned nil for a nonce-configured verifier")
	}
}

// TestRequireBearerTokenAllowsNonNonceDPoP proves DPoP enforcement WITHOUT a
// nonce constructs without panic on the SDK path -- only the nonce response
// hook is missing, so plain DPoP and the no-DPoP verifier are fine.
func TestRequireBearerTokenAllowsNonNonceDPoP(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	// Neither construction should panic.
	_ = mcpauth.RequireBearerToken(v, &mcpauth.Options{DPoP: dpop.NewVerifier(dpop.Config{})})
	_ = mcpauth.NewTokenVerifier(v)
}

// TestRequireBearerTokenWithMultiValidator proves the SDK bearer path accepts an
// auth.MultiValidator through the widened TokenValidator parameter: a token from
// a configured issuer reaches the handler with its claims (Issuer set)
// recoverable via ClaimsFromContext, and an unknown issuer is rejected 401.
func TestRequireBearerTokenWithMultiValidator(t *testing.T) {
	jA := jwkstest.New(t)
	jB := jwkstest.New(t)
	const (
		issA = "https://issuer-a.example.com"
		issB = "https://issuer-b.example.com"
		audA = "https://mcp-a.example.com"
		audB = "https://mcp-b.example.com"
	)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mv, err := auth.NewMultiValidator(ctx, auth.MultiValidatorConfig{
		Issuers: []auth.ValidatorConfig{
			{JWKSURL: jA.URL(), Issuer: issA, Audience: audA},
			{JWKSURL: jB.URL(), Issuer: issB, Audience: audB},
		},
	})
	if err != nil {
		t.Fatalf("NewMultiValidator: %v", err)
	}

	var gotIssuer string
	var gotOK bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := mcpauth.ClaimsFromContext(r.Context())
		gotOK = ok
		if ok {
			gotIssuer = c.Issuer
		}
		w.WriteHeader(http.StatusOK)
	})
	h := mcpauth.RequireBearerToken(mv, nil)(next)

	tokenA := jA.Mint(t, jwkstest.ClaimSet{Subject: "alice", Issuer: issA, Audience: audA})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tokenA)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body)
	}
	if !gotOK || gotIssuer != issA {
		t.Errorf("ClaimsFromContext issuer = %q ok=%v, want %q true", gotIssuer, gotOK, issA)
	}

	bad := jB.Mint(t, jwkstest.ClaimSet{Subject: "x", Issuer: "https://unconfigured.example.com", Audience: audB})
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req2.Header.Set("Authorization", "Bearer "+bad)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("unknown-issuer status = %d, want 401", rec2.Code)
	}
}

// Compile-time proof the widened validator parameter (auth.TokenValidator) on
// NewTokenVerifier / RequireBearerToken is satisfied by both the single-issuer
// Validator and the MultiValidator, so the widening is backward-compatible.
var (
	_ auth.TokenValidator = (*auth.Validator)(nil)
	_ auth.TokenValidator = (*auth.MultiValidator)(nil)
)
