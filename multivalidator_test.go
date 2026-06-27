package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
)

// Distinct iss/aud per test issuer. jwkstest.New defaults both issuers to the
// same iss/aud, so multi-issuer routing needs explicit, distinct values
// configured on the sub-Validators and minted into the tokens.
const (
	miIssuerA   = "https://issuer-a.example.com/oauth2/aus_a"
	miIssuerB   = "https://issuer-b.example.com/oauth2/aus_b"
	miAudienceA = "https://mcp-a.example.com"
	miAudienceB = "https://mcp-b.example.com"
)

// twoIssuerValidator builds a MultiValidator over two independent JWKS issuers A
// and B, optionally attaching authorization verifiers to issuer A.
func twoIssuerValidator(t testing.TB, jA, jB *jwkstest.JWKS, verifiersA ...auth.ClaimVerifier) *auth.MultiValidator {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mv, err := auth.NewMultiValidator(ctx, auth.MultiValidatorConfig{
		Issuers: []auth.ValidatorConfig{
			{JWKSURL: jA.URL(), Issuer: miIssuerA, Audience: miAudienceA, MinRefreshInterval: time.Minute, ClockSkew: 5 * time.Second, Verifiers: verifiersA},
			{JWKSURL: jB.URL(), Issuer: miIssuerB, Audience: miAudienceB, MinRefreshInterval: time.Minute, ClockSkew: 5 * time.Second},
		},
	})
	if err != nil {
		t.Fatalf("NewMultiValidator: %v", err)
	}
	return mv
}

// peekToken builds a JWT carrying iss (omitted when hasIss is false) signed by a
// throwaway key. The signature is irrelevant: these tokens exercise the
// unverified iss peek, which routes -- and here fails closed -- before any
// signature check runs.
func peekToken(t testing.TB, iss string, hasIss bool) string {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	key, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	b := jwt.NewBuilder().Subject("x").Audience([]string{"y"}).Expiration(time.Now().Add(time.Hour))
	if hasIss {
		b = b.Issuer(iss)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// TestMultiValidatorRouting proves the unverified-iss peek routes a well-formed
// token to its issuer's Validator and fails closed (ErrInvalidToken) on an
// unknown, missing, empty, or malformed iss -- empty bearer surfaces
// ErrMissingToken.
func TestMultiValidatorRouting(t *testing.T) {
	jA := jwkstest.New(t)
	jB := jwkstest.New(t)
	mv := twoIssuerValidator(t, jA, jB)

	tokenA := jA.Mint(t, jwkstest.ClaimSet{Subject: "alice", Issuer: miIssuerA, Audience: miAudienceA})
	tokenB := jB.Mint(t, jwkstest.ClaimSet{Subject: "bob", Issuer: miIssuerB, Audience: miAudienceB})
	tokenUnknown := jA.Mint(t, jwkstest.ClaimSet{Subject: "x", Issuer: "https://unconfigured.example.com", Audience: miAudienceA})
	tokenExpiredA := jA.Mint(t, jwkstest.ClaimSet{Subject: "carol", Issuer: miIssuerA, Audience: miAudienceA, NotAfter: -time.Minute})

	tests := []struct {
		name       string
		token      string
		wantErr    error  // nil ⇒ expect success
		wantIssuer string // checked only when wantErr is nil
	}{
		{name: "routes to issuer A", token: tokenA, wantIssuer: miIssuerA},
		{name: "routes to issuer B", token: tokenB, wantIssuer: miIssuerB},
		{name: "unknown issuer", token: tokenUnknown, wantErr: auth.ErrInvalidToken},
		{name: "expired token routes to A then ErrExpiredToken", token: tokenExpiredA, wantErr: auth.ErrExpiredToken},
		{name: "missing iss", token: peekToken(t, "", false), wantErr: auth.ErrInvalidToken},
		{name: "empty iss", token: peekToken(t, "", true), wantErr: auth.ErrInvalidToken},
		{name: "malformed token", token: "not.a.jwt", wantErr: auth.ErrInvalidToken},
		{name: "empty bearer", token: "", wantErr: auth.ErrMissingToken},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			claims, err := mv.Validate(context.Background(), tc.token)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					st.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				st.Fatalf("unexpected error: %v", err)
			}
			if claims.Issuer != tc.wantIssuer {
				st.Errorf("Issuer = %q, want %q", claims.Issuer, tc.wantIssuer)
			}
		})
	}
}

// TestMultiValidatorAudienceIsolation proves the audience is enforced PER
// issuer: a token routed to A but carrying B's audience is rejected by A's
// Validator, not silently accepted against some global audience.
func TestMultiValidatorAudienceIsolation(t *testing.T) {
	jA := jwkstest.New(t)
	jB := jwkstest.New(t)
	mv := twoIssuerValidator(t, jA, jB)

	token := jA.Mint(t, jwkstest.ClaimSet{Subject: "alice", Issuer: miIssuerA, Audience: miAudienceB})
	_, err := mv.Validate(context.Background(), token)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

// TestMultiValidatorCrossIssuerSignature proves the peek does not bypass crypto:
// a token signed by A's key but claiming iss=B routes to B, whose JWKS cannot
// verify A's signature.
func TestMultiValidatorCrossIssuerSignature(t *testing.T) {
	jA := jwkstest.New(t)
	jB := jwkstest.New(t)
	mv := twoIssuerValidator(t, jA, jB)

	token := jA.Mint(t, jwkstest.ClaimSet{Subject: "mallory", Issuer: miIssuerB, Audience: miAudienceB})
	_, err := mv.Validate(context.Background(), token)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

// TestNewMultiValidatorValidation proves construction fails fast on an empty
// set, a duplicate issuer, a missing required sub-field, and an unreachable
// JWKS, and succeeds on a valid config.
func TestNewMultiValidatorValidation(t *testing.T) {
	jA := jwkstest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	live := auth.ValidatorConfig{JWKSURL: jA.URL(), Issuer: miIssuerA, Audience: miAudienceA}

	tests := []struct {
		name    string
		issuers []auth.ValidatorConfig
		wantErr string // substring; "" ⇒ expect success
	}{
		{name: "empty issuers", issuers: nil, wantErr: "at least one issuer"},
		{name: "missing jwks url", issuers: []auth.ValidatorConfig{{Issuer: miIssuerA, Audience: miAudienceA}}, wantErr: "required"},
		{name: "duplicate issuer", issuers: []auth.ValidatorConfig{live, live}, wantErr: "duplicate"},
		{name: "unreachable jwks", issuers: []auth.ValidatorConfig{{JWKSURL: "http://127.0.0.1:1/jwks", Issuer: miIssuerA, Audience: miAudienceA}}, wantErr: "initial jwks fetch"},
		{name: "valid", issuers: []auth.ValidatorConfig{live}, wantErr: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			_, err := auth.NewMultiValidator(ctx, auth.MultiValidatorConfig{Issuers: tc.issuers})
			if tc.wantErr == "" {
				if err != nil {
					st.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				st.Errorf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestMultiValidatorNoIssuerInError proves the attacker-supplied iss never
// appears in the error surface and the unknown-issuer cause is the documented
// constant.
func TestMultiValidatorNoIssuerInError(t *testing.T) {
	jA := jwkstest.New(t)
	jB := jwkstest.New(t)
	mv := twoIssuerValidator(t, jA, jB)

	const marker = "attacker-marker-12345"
	token := jA.Mint(t, jwkstest.ClaimSet{Subject: "x", Issuer: marker, Audience: miAudienceA})
	_, err := mv.Validate(context.Background(), token)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("error surface leaked the attacker iss: %v", err)
	}
	if !strings.Contains(err.Error(), "issuer not configured") {
		t.Errorf("error = %v, want constant cause %q", err, "issuer not configured")
	}
}

// TestMultiValidatorNoFetchOnUnknownIssuer proves the unknown-issuer path fails
// closed WITHOUT any JWKS fetch (spec E3): no JWKS URL is ever derived from the
// token. A counting JWKS server records hits; the unknown-iss Validate call must
// not increment the count past the one synchronous fetch at construction.
func TestMultiValidatorNoFetchOnUnknownIssuer(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mv, err := auth.NewMultiValidator(ctx, auth.MultiValidatorConfig{
		Issuers: []auth.ValidatorConfig{
			{JWKSURL: srv.URL, Issuer: miIssuerA, Audience: miAudienceA, MinRefreshInterval: time.Hour},
		},
	})
	if err != nil {
		t.Fatalf("NewMultiValidator: %v", err)
	}

	token := peekToken(t, "https://unconfigured.example.com", true)
	before := atomic.LoadInt64(&hits)
	_, verr := mv.Validate(context.Background(), token)
	after := atomic.LoadInt64(&hits)

	if !errors.Is(verr, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", verr)
	}
	if after != before {
		t.Errorf("unknown-issuer path fetched JWKS: hits %d → %d (want no fetch)", before, after)
	}
}

// TestMultiValidatorVerifierPropagation proves a matched issuer's authorization
// verifiers run and their typed errors surface unchanged.
func TestMultiValidatorVerifierPropagation(t *testing.T) {
	jA := jwkstest.New(t)
	jB := jwkstest.New(t)
	mv := twoIssuerValidator(t, jA, jB,
		auth.RequireScopes("mcp:read"),
		auth.VerifyRequiredStringClaims(map[string]string{"tier": "internal"}),
	)

	tests := []struct {
		name    string
		claims  jwkstest.ClaimSet
		wantErr error // nil ⇒ expect success
	}{
		{
			name:    "missing scope",
			claims:  jwkstest.ClaimSet{Subject: "a", Issuer: miIssuerA, Audience: miAudienceA, Private: map[string]any{"tier": "internal"}},
			wantErr: auth.ErrInsufficientScope,
		},
		{
			name:    "wrong required claim",
			claims:  jwkstest.ClaimSet{Subject: "a", Issuer: miIssuerA, Audience: miAudienceA, Private: map[string]any{"scope": "mcp:read", "tier": "external"}},
			wantErr: auth.ErrForbidden,
		},
		{
			name:   "all satisfied",
			claims: jwkstest.ClaimSet{Subject: "a", Issuer: miIssuerA, Audience: miAudienceA, Private: map[string]any{"scope": "mcp:read", "tier": "internal"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			token := jA.Mint(st, tc.claims)
			_, err := mv.Validate(context.Background(), token)
			if tc.wantErr == nil {
				if err != nil {
					st.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				st.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestMultiValidatorConcurrency proves Validate is safe for concurrent use
// across issuers (byIssuer is read-only after construction). Run with -race.
func TestMultiValidatorConcurrency(t *testing.T) {
	jA := jwkstest.New(t)
	jB := jwkstest.New(t)
	mv := twoIssuerValidator(t, jA, jB)

	tokenA := jA.Mint(t, jwkstest.ClaimSet{Subject: "alice", Issuer: miIssuerA, Audience: miAudienceA})
	tokenB := jB.Mint(t, jwkstest.ClaimSet{Subject: "bob", Issuer: miIssuerB, Audience: miAudienceB})

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := range goroutines {
		wg.Go(func() {
			token, wantIss := tokenA, miIssuerA
			if i%2 == 1 {
				token, wantIss = tokenB, miIssuerB
			}
			claims, err := mv.Validate(context.Background(), token)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", i, err)
				return
			}
			if claims.Issuer != wantIss {
				errs <- fmt.Errorf("goroutine %d: Issuer = %q, want %q", i, claims.Issuer, wantIss)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
