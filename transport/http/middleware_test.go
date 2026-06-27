package http

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
)

// The middleware tests configure the validator with a generic required-claim
// verifier so they exercise verifier injection, not any product policy.
const (
	reqClaim = "tier"
	reqValue = "internal"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newValidator builds a Validator pointed at the test JWKS that requires
// reqClaim=reqValue via an injected verifier.
func newValidator(t *testing.T, j *jwkstest.JWKS) *auth.Validator {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:            j.URL(),
		Issuer:             j.Issuer(),
		Audience:           j.Audience(),
		MinRefreshInterval: time.Minute,
		ClockSkew:          5 * time.Second,
		Verifiers: []auth.ClaimVerifier{
			auth.VerifyRequiredStringClaims(map[string]string{reqClaim: reqValue}),
		},
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// stubLimiter is a deterministic RateLimiter for middleware tests.
type stubLimiter struct {
	allow      bool
	retryAfter time.Duration
	gotKey     string
	calls      int
}

func (s *stubLimiter) Allow(key string, _ time.Time) (bool, time.Duration) {
	s.gotKey = key
	s.calls++
	return s.allow, s.retryAfter
}

// passthroughHandler returns 200 and lets the test verify whether the
// middleware called next (i.e. the request was authorized).
func passthroughHandler() (http.Handler, *bool) {
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Sanity: claims must be on the context when we reach here.
		if _, ok := auth.ClaimsFrom(r.Context()); !ok {
			http.Error(w, "no claims in context", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return h, &called
}

// TestMiddlewareHappyPath proves a valid Bearer token with the required claim
// reaches the next handler and the rate limiter is keyed on the subject.
func TestMiddlewareHappyPath(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	limiter := &stubLimiter{allow: true}

	mw := MiddlewareConfig{
		Validator:   v,
		RateLimiter: limiter,
		Logger:      discardLogger(),
		Now:         time.Now,
	}.Middleware()

	next, called := passthroughHandler()
	handler := mw(next)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: reqValue},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body = %s", rr.Code, rr.Body)
	}
	if !*called {
		t.Errorf("middleware did not invoke next on happy path")
	}
	if limiter.gotKey != "alice" {
		t.Errorf("rate limiter keyed on %q, want alice", limiter.gotKey)
	}
}

// TestMiddlewareRejectsMissingHeader proves a request with no Authorization
// header gets a 401 missing_token response and a Bearer challenge.
func TestMiddlewareRejectsMissingHeader(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{Validator: v, Logger: discardLogger()}.Middleware()
	next, called := passthroughHandler()
	handler := mw(next)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if *called {
		t.Errorf("middleware called next without auth")
	}
	assertJSONError(t, rr, "missing_token")
	if wa := rr.Header().Get("WWW-Authenticate"); !strings.Contains(wa, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want Bearer challenge", wa)
	}
}

// TestMiddlewareRejectsNonBearer proves malformed Authorization headers are
// rejected with 401 and the next handler is never invoked.
func TestMiddlewareRejectsNonBearer(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{Validator: v, Logger: discardLogger()}.Middleware()
	next, called := passthroughHandler()
	handler := mw(next)

	tests := []struct {
		name   string
		header string
	}{
		{name: "basic scheme", header: "Basic abc"},
		{name: "lowercase bearer no space", header: "bearer no-cap-no-space"},
		{name: "bearer with only spaces", header: "Bearer  "},
		{name: "bare bearer", header: "Bearer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			req.Header.Set("Authorization", tc.header)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				st.Errorf("header %q: status = %d, want 401", tc.header, rr.Code)
			}
		})
	}
	if *called {
		t.Errorf("middleware called next with malformed header")
	}
}

// TestMiddlewareEnforcesRequiredClaim is an acceptance test: a token missing
// the required claim must produce 403 forbidden, the next handler must NOT be
// invoked, and the cause (claim name) must not leak into the body.
func TestMiddlewareEnforcesRequiredClaim(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{Validator: v, Logger: discardLogger()}.Middleware()
	next, called := passthroughHandler()
	handler := mw(next)

	token := j.Mint(t, jwkstest.ClaimSet{Subject: "alice"}) // no required claim

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if *called {
		t.Fatalf("middleware called next despite forbidden rejection")
	}
	assertJSONError(t, rr, "forbidden")
	// The cause names the failing claim; it must never reach the public body.
	if strings.Contains(rr.Body.String(), reqClaim) {
		t.Errorf("body leaks the failing claim name: %s", rr.Body.String())
	}
}

// TestMiddlewareEnforcesRequiredClaimOnWrongValue proves a token with the
// required claim set to a non-matching value is rejected with 403.
func TestMiddlewareEnforcesRequiredClaimOnWrongValue(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{Validator: v, Logger: discardLogger()}.Middleware()
	next, _ := passthroughHandler()
	handler := mw(next)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: "external"},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

// TestMiddlewareExpiredToken proves an expired token is rejected with 401 and
// an expired_token error code.
func TestMiddlewareExpiredToken(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{Validator: v, Logger: discardLogger()}.Middleware()
	next, _ := passthroughHandler()
	handler := mw(next)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject:  "alice",
		NotAfter: -time.Minute,
		Private:  map[string]any{reqClaim: reqValue},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	assertJSONError(t, rr, "expired_token")
}

// TestMiddlewareRateLimited proves a denied limiter response yields a 429 with
// the configured Retry-After and a rate_limit_exceeded body.
func TestMiddlewareRateLimited(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	limiter := &stubLimiter{allow: false, retryAfter: 45 * time.Second}
	mw := MiddlewareConfig{
		Validator:   v,
		RateLimiter: limiter,
		Logger:      discardLogger(),
		Now:         time.Now,
	}.Middleware()
	next, called := passthroughHandler()
	handler := mw(next)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: reqValue},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if *called {
		t.Fatalf("middleware called next despite rate limit")
	}
	if got := rr.Header().Get("Retry-After"); got != "45" {
		t.Errorf("Retry-After = %q, want 45", got)
	}
	assertJSONError(t, rr, "rate_limit_exceeded")
}

// TestMiddlewareNoRateLimiterIsOptional proves a nil RateLimiter is allowed
// and authorized requests pass through.
func TestMiddlewareNoRateLimiterIsOptional(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{
		Validator: v,
		Logger:    discardLogger(),
		// RateLimiter intentionally nil
	}.Middleware()
	next, called := passthroughHandler()
	handler := mw(next)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: reqValue},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !*called {
		t.Errorf("nil RateLimiter should be allowed: status=%d called=%v", rr.Code, *called)
	}
}

// TestMiddlewareErrorBodyOmitsCause proves auth-rejection responses never
// expose the cause or http_status fields.
func TestMiddlewareErrorBodyOmitsCause(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{Validator: v, Logger: discardLogger()}.Middleware()
	next, _ := passthroughHandler()
	handler := mw(next)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-a-jwt")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		DocURL  string `json:"doc_url"`
		Cause   string `json:"cause,omitempty"` // must be empty
		HTTP    int    `json:"http_status,omitempty"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body)
	}
	if body.Cause != "" {
		t.Errorf("Cause leaked: %q", body.Cause)
	}
	if body.HTTP != 0 {
		t.Errorf("HTTP status leaked into body: %d", body.HTTP)
	}
}

// TestMiddlewareChallengeIncludesResourceMetadata proves a 401 challenge
// carries the RFC 9728 resource_metadata pointer, and that a missing-token
// rejection omits the RFC 6750 error parameter (missing_token is not a
// registered code, and the request carried no credentials).
func TestMiddlewareChallengeIncludesResourceMetadata(t *testing.T) {
	const prm = "https://mcp.example.com/.well-known/oauth-protected-resource"
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{
		Validator:           v,
		Logger:              discardLogger(),
		ResourceMetadataURL: prm,
	}.Middleware()
	next, _ := passthroughHandler()
	handler := mw(next)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil) // no Authorization → 401
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	wa := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, `resource_metadata="`+prm+`"`) {
		t.Errorf("WWW-Authenticate = %q, want resource_metadata pointer", wa)
	}
	if strings.Contains(wa, "error=") {
		t.Errorf("WWW-Authenticate = %q, missing-token challenge must omit error param", wa)
	}
}

// TestMiddlewareExpiredChallengeMapsToInvalidToken proves the expired-token
// rejection advertises the registered RFC 6750 code (invalid_token) in the
// challenge, even though the JSON body keeps the granular expired_token code.
func TestMiddlewareExpiredChallengeMapsToInvalidToken(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	mw := MiddlewareConfig{Validator: v, Logger: discardLogger()}.Middleware()
	next, _ := passthroughHandler()
	handler := mw(next)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject:  "alice",
		NotAfter: -time.Minute,
		Private:  map[string]any{reqClaim: reqValue},
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assertJSONError(t, rr, "expired_token") // body keeps the granular code
	if wa := rr.Header().Get("WWW-Authenticate"); !strings.Contains(wa, `error="invalid_token"`) {
		t.Errorf("challenge = %q, want error=invalid_token (RFC 6750)", wa)
	}
}

// TestMiddlewareInsufficientScopeChallenge proves a token lacking a required
// scope yields 403 insufficient_scope with the RFC 6750 scope parameter so a
// client can request step-up authorization.
func TestMiddlewareInsufficientScopeChallenge(t *testing.T) {
	j := jwkstest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:   j.URL(),
		Issuer:    j.Issuer(),
		Audience:  j.Audience(),
		Verifiers: []auth.ClaimVerifier{auth.RequireScopes("mcp:write")},
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	mw := MiddlewareConfig{
		Validator:           v,
		Logger:              discardLogger(),
		ResourceMetadataURL: "https://mcp.example.com/.well-known/oauth-protected-resource",
		Scopes:              []string{"mcp:write"},
	}.Middleware()
	next, called := passthroughHandler()
	handler := mw(next)

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
	if *called {
		t.Fatalf("next called despite insufficient scope")
	}
	assertJSONError(t, rr, "insufficient_scope")
	wa := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, `error="insufficient_scope"`) {
		t.Errorf("challenge = %q, want error=insufficient_scope", wa)
	}
	if !strings.Contains(wa, `scope="mcp:write"`) {
		t.Errorf("challenge = %q, want scope=mcp:write", wa)
	}
}

// TestMiddlewareWithMultiValidator proves the HTTP middleware accepts an
// auth.MultiValidator through the widened TokenValidator field: a token from a
// configured issuer reaches the handler with its claims, and a token carrying
// the wrong audience for its issuer is rejected 401.
func TestMiddlewareWithMultiValidator(t *testing.T) {
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

	mw := MiddlewareConfig{Validator: mv, Logger: discardLogger()}.Middleware()

	var gotIssuer string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := auth.ClaimsFrom(r.Context()); ok {
			gotIssuer = c.Issuer
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(next)

	tokenB := jB.Mint(t, jwkstest.ClaimSet{Subject: "bob", Issuer: issB, Audience: audB})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rr.Code, rr.Body)
	}
	if gotIssuer != issB {
		t.Errorf("claims.Issuer = %q, want %q", gotIssuer, issB)
	}

	// A token signed by issuer A but carrying issuer B's audience is rejected.
	bad := jA.Mint(t, jwkstest.ClaimSet{Subject: "x", Issuer: issA, Audience: audB})
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req2.Header.Set("Authorization", "Bearer "+bad)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("wrong-audience status = %d, want 401", rr2.Code)
	}
}

// Compile-time proof the widened MiddlewareConfig.Validator (auth.TokenValidator)
// is satisfied by both the single-issuer Validator and the MultiValidator, so
// the widening is backward-compatible.
var (
	_ auth.TokenValidator = (*auth.Validator)(nil)
	_ auth.TokenValidator = (*auth.MultiValidator)(nil)
)

// assertJSONError checks the response is a JSON error body with the expected
// code.
func assertJSONError(t *testing.T, rr *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body auth.Error
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v; raw=%s", err, rr.Body)
	}
	if body.Code != wantCode {
		t.Errorf("error code = %q, want %q (raw=%s)", body.Code, wantCode, rr.Body)
	}
}

// TestSetRetryAfter proves Retry-After is emitted as a non-negative integer
// (RFC 9110), rounding fractional seconds up, and is omitted entirely for zero
// or negative durations.
func TestSetRetryAfter(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string // "" => the header must be unset
	}{
		{name: "sub-second rounds up to 1", d: 100 * time.Millisecond, want: "1"},
		{name: "fractional rounds up", d: 7*time.Second + 500*time.Millisecond, want: "8"},
		{name: "zero is omitted", d: 0, want: ""},
		{name: "negative is omitted", d: -time.Second, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			w := httptest.NewRecorder()
			setRetryAfter(w, tc.d)
			if got := w.Header().Get("Retry-After"); got != tc.want {
				st.Errorf("d=%v: Retry-After = %q, want %q", tc.d, got, tc.want)
			}
		})
	}
}

// TestExtractBearer proves the extracted bearer is the trimmed token text and
// that malformed headers produce an error.
func TestExtractBearer(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{name: "happy", header: "Bearer abc", want: "abc", wantErr: false},
		{name: "happy trimmed", header: "Bearer  abc ", want: "abc", wantErr: false},
		{name: "case insensitive", header: "bearer abc", want: "abc", wantErr: false},
		{name: "empty", header: "", want: "", wantErr: true},
		{name: "basic scheme", header: "Basic xyz", want: "", wantErr: true},
		{name: "bare", header: "Bearer", want: "", wantErr: true},
		{name: "only spaces", header: "Bearer    ", want: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			tok, err := extractBearer(req)
			if (err != nil) != tc.wantErr {
				st.Fatalf("err = %v, wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && tok != tc.want {
				st.Errorf("token = %q, want %q", tok, tc.want)
			}
		})
	}
}

// TestMiddlewarePropagatesRawToken proves the raw bearer token is placed on
// the request context by the middleware so downstream helpers (e.g. an RFC 8693
// token-exchange broker) can retrieve it via auth.RawTokenFrom.
func TestMiddlewarePropagatesRawToken(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	cfg := MiddlewareConfig{
		Validator: v,
		Logger:    discardLogger(),
	}

	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: reqValue},
	})

	var seen string
	var seenOK bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, seenOK = auth.RawTokenFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	srv := cfg.Middleware()(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if !seenOK || seen != tok {
		t.Fatalf("handler saw raw token %q, %v; want %q, true", seen, seenOK, tok)
	}
}

// --- DPoP enforcement tests ---

// dpopTestKey generates a fresh ES256 key for DPoP test proofs.
func dpopTestKey(t *testing.T) jwk.Key {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = k.Set(jwk.AlgorithmKey, jwa.ES256)
	return k
}

// dpopThumbprint returns the base64url SHA-256 JWK thumbprint of k's public key.
func dpopThumbprint(t *testing.T, k jwk.Key) string {
	t.Helper()
	pub, _ := k.PublicKey()
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// dpopAth computes the base64url SHA-256 of the access token for the ath claim.
func dpopAth(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// dpopBuildProof builds a DPoP proof JWT signed by k with the given claims.
func dpopBuildProof(t *testing.T, k jwk.Key, claims map[string]any) string {
	t.Helper()
	pub, _ := k.PublicKey()
	payload, _ := json.Marshal(claims)
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.TypeKey, "dpop+jwt")
	_ = hdr.Set(jws.JWKKey, pub)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, k, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// okHandlerFunc is a simple handler that writes 200.
var okHandlerFunc = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// TestMiddlewareDPoPBoundTokenWithValidProof proves a DPoP-bound token paired
// with a valid proof reaches the handler (happy path).
func TestMiddlewareDPoPBoundTokenWithValidProof(t *testing.T) {
	j := jwkstest.New(t)
	k := dpopTestKey(t)
	jkt := dpopThumbprint(t, k)

	// Mint a token carrying cnf.jkt (the binding thumbprint).
	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{
			reqClaim: reqValue,
			"cnf":    map[string]any{"jkt": jkt},
		},
	})

	dv := dpop.NewVerifier(dpop.Config{ReplayCache: dpop.NewNopReplayCache()})
	cfg := MiddlewareConfig{
		Validator: newValidator(t, j),
		Logger:    discardLogger(),
		DPoP:      dv,
	}

	const method = http.MethodPost
	const path = "/tools/call"

	proof := dpopBuildProof(t, k, map[string]any{
		"jti": "id-happy",
		"htm": method,
		"htu": "http://example.com" + path, // reconstructed from req (http, no TLS)
		"iat": time.Now().Unix(),
		"ath": dpopAth(tok),
	})

	req := httptest.NewRequest(method, path, nil)
	req.Host = "example.com"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("DPoP", proof)

	rec := httptest.NewRecorder()
	cfg.Middleware()(okHandlerFunc).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body: %s)", rec.Code, rec.Body)
	}
}

// TestMiddlewareNonceChallengeThenAccept walks the RFC 9449 §9 round-trip: a
// valid proof with no nonce is challenged (401 + DPoP scheme + use_dpop_nonce +
// a DPoP-Nonce header), and a retry carrying that issued nonce succeeds and
// rotates a fresh nonce onto the 200. Real time is used end-to-end (no injected
// clock), matching the other DPoP middleware tests.
func TestMiddlewareNonceChallengeThenAccept(t *testing.T) {
	j := jwkstest.New(t)
	k := dpopTestKey(t)
	jkt := dpopThumbprint(t, k)
	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: reqValue, "cnf": map[string]any{"jkt": jkt}},
	})
	ns, err := dpop.NewSignedNonce([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	cfg := MiddlewareConfig{
		Validator: newValidator(t, j),
		Logger:    discardLogger(),
		DPoP:      dpop.NewVerifier(dpop.Config{Nonce: ns}),
	}
	srv := cfg.Middleware()(okHandlerFunc)

	const method, path, htu = http.MethodPost, "/tools/call", "http://example.com/tools/call"

	// Step 1: a valid proof WITHOUT a nonce -> 401 nonce challenge.
	proof1 := dpopBuildProof(t, k, map[string]any{
		"jti": "j1", "htm": method, "htu": htu, "iat": time.Now().Unix(), "ath": dpopAth(tok),
	})
	req1 := httptest.NewRequest(method, path, nil)
	req1.Host = "example.com"
	req1.Header.Set("Authorization", "Bearer "+tok)
	req1.Header.Set("DPoP", proof1)
	rec1 := httptest.NewRecorder()
	srv.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("step 1 status = %d; want 401 (body: %s)", rec1.Code, rec1.Body)
	}
	if wa := rec1.Header().Get("WWW-Authenticate"); !strings.HasPrefix(wa, "DPoP ") || !strings.Contains(wa, `error="use_dpop_nonce"`) {
		t.Fatalf("step 1 challenge = %q; want DPoP scheme + use_dpop_nonce", wa)
	}
	issued := rec1.Header().Get("DPoP-Nonce")
	if issued == "" {
		t.Fatal("step 1 must set a non-empty DPoP-Nonce header")
	}

	// Step 2: retry WITH the issued nonce -> 200, rotated nonce + no-store.
	proof2 := dpopBuildProof(t, k, map[string]any{
		"jti": "j2", "htm": method, "htu": htu, "iat": time.Now().Unix(), "ath": dpopAth(tok), "nonce": issued,
	})
	req2 := httptest.NewRequest(method, path, nil)
	req2.Host = "example.com"
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("DPoP", proof2)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("step 2 status = %d; want 200 (body: %s)", rec2.Code, rec2.Body)
	}
	if rec2.Header().Get("DPoP-Nonce") == "" {
		t.Fatal("step 2 success must rotate a fresh DPoP-Nonce")
	}
	if rec2.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("step 2 success must set Cache-Control: no-store")
	}
}

// TestMiddlewareDPoPWithoutNonceEmitsNoNonceHeader proves nonce is fully opt-in:
// a DPoP verifier with no NonceSource neither demands nor rotates a DPoP-Nonce.
func TestMiddlewareDPoPWithoutNonceEmitsNoNonceHeader(t *testing.T) {
	j := jwkstest.New(t)
	k := dpopTestKey(t)
	jkt := dpopThumbprint(t, k)
	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: reqValue, "cnf": map[string]any{"jkt": jkt}},
	})
	cfg := MiddlewareConfig{
		Validator: newValidator(t, j),
		Logger:    discardLogger(),
		DPoP:      dpop.NewVerifier(dpop.Config{}), // DPoP, but no nonce
	}

	const method, path, htu = http.MethodPost, "/tools/call", "http://example.com/tools/call"
	proof := dpopBuildProof(t, k, map[string]any{
		"jti": "j1", "htm": method, "htu": htu, "iat": time.Now().Unix(), "ath": dpopAth(tok),
	})
	req := httptest.NewRequest(method, path, nil)
	req.Host = "example.com"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	cfg.Middleware()(okHandlerFunc).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (no nonce demanded; body: %s)", rec.Code, rec.Body)
	}
	if rec.Header().Get("DPoP-Nonce") != "" {
		t.Fatal("no DPoP-Nonce must be emitted when nonce is unconfigured")
	}
}

// TestMiddlewareDPoPBoundTokenWithoutProof proves a DPoP-bound token presented
// with NO DPoP header returns 401 with a DPoP-scheme challenge.
func TestMiddlewareDPoPBoundTokenWithoutProof(t *testing.T) {
	j := jwkstest.New(t)
	k := dpopTestKey(t)
	jkt := dpopThumbprint(t, k)

	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{
			reqClaim: reqValue,
			"cnf":    map[string]any{"jkt": jkt},
		},
	})

	dv := dpop.NewVerifier(dpop.Config{})
	cfg := MiddlewareConfig{
		Validator: newValidator(t, j),
		Logger:    discardLogger(),
		DPoP:      dv,
	}

	req := httptest.NewRequest(http.MethodPost, "/tools/call", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	// Deliberately no DPoP header.

	rec := httptest.NewRecorder()
	cfg.Middleware()(okHandlerFunc).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wa, "DPoP ") {
		t.Fatalf("challenge = %q; want DPoP scheme", wa)
	}
	if !strings.Contains(wa, `error="invalid_dpop_proof"`) {
		t.Fatalf("challenge = %q; want invalid_dpop_proof", wa)
	}
}

// TestMiddlewareDPoPOpportunisticUnbound proves an unbound token (no cnf.jkt)
// passes through when DPoP is Opportunistic (the default).
func TestMiddlewareDPoPOpportunisticUnbound(t *testing.T) {
	j := jwkstest.New(t)

	// Token has no cnf claim — unbound.
	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: reqValue},
	})

	dv := dpop.NewVerifier(dpop.Config{Mode: dpop.Opportunistic})
	cfg := MiddlewareConfig{
		Validator: newValidator(t, j),
		Logger:    discardLogger(),
		DPoP:      dv,
	}

	req := httptest.NewRequest(http.MethodGet, "/tools/list", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	rec := httptest.NewRecorder()
	cfg.Middleware()(okHandlerFunc).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("opportunistic+unbound: status = %d; want 200", rec.Code)
	}
}

// TestMiddlewareDPoPRequireRejectsUnbound proves Mode=Require rejects an
// unbound token (no cnf.jkt) with 401.
func TestMiddlewareDPoPRequireRejectsUnbound(t *testing.T) {
	j := jwkstest.New(t)

	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{reqClaim: reqValue},
	})

	dv := dpop.NewVerifier(dpop.Config{Mode: dpop.Require})
	cfg := MiddlewareConfig{
		Validator: newValidator(t, j),
		Logger:    discardLogger(),
		DPoP:      dv,
	}

	req := httptest.NewRequest(http.MethodGet, "/tools/list", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	rec := httptest.NewRecorder()
	cfg.Middleware()(okHandlerFunc).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("require+unbound: status = %d; want 401", rec.Code)
	}
}

// TestMiddlewareDPoPBaseURLOverride proves BaseURL makes a proxied-path proof
// match when the request host reflects the internal hop.
func TestMiddlewareDPoPBaseURLOverride(t *testing.T) {
	j := jwkstest.New(t)
	k := dpopTestKey(t)
	jkt := dpopThumbprint(t, k)

	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{
			reqClaim: reqValue,
			"cnf":    map[string]any{"jkt": jkt},
		},
	})

	const publicBase = "https://mcp.example.com"
	const path = "/tools/call"

	// The client signed the proof against the public URL.
	proof := dpopBuildProof(t, k, map[string]any{
		"jti": "id-proxy",
		"htm": http.MethodPost,
		"htu": publicBase + path, // public URL the client sees
		"iat": time.Now().Unix(),
		"ath": dpopAth(tok),
	})

	dv := dpop.NewVerifier(dpop.Config{ReplayCache: dpop.NewNopReplayCache()})
	cfg := MiddlewareConfig{
		Validator: newValidator(t, j),
		Logger:    discardLogger(),
		DPoP:      dv,
		BaseURL:   publicBase, // tell the middleware to use the public base
	}

	// The request arrives at the internal hop — different host, no TLS.
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Host = "internal-lb.cluster.local"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("DPoP", proof)

	rec := httptest.NewRecorder()
	cfg.Middleware()(okHandlerFunc).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("BaseURL override: status = %d; want 200 (body: %s)", rec.Code, rec.Body)
	}
}

// TestMiddlewareSlogNoTokenLeak guards the real log surface (writeAuthError)
// against a future change that accidentally logs the bearer token or its ath
// preimage. A bound token presented without a DPoP header flows through
// writeAuthError which logs slog.Any("cause", e.Cause); the cause must be a
// constant string that contains neither the token value nor its SHA-256 hash.
func TestMiddlewareSlogNoTokenLeak(t *testing.T) {
	j := jwkstest.New(t)
	k := dpopTestKey(t)
	jkt := dpopThumbprint(t, k)

	// Mint a DPoP-bound token (cnf.jkt present). The middleware will call
	// DPoP.Enforce after validating the token, discover zero DPoP headers, and
	// reject with ErrInvalidDPoPProof. writeAuthError then logs the cause.
	// We assert on tok — the actual JWT string — because that is the real secret
	// that must not appear in log output.
	tok := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{
			reqClaim: reqValue,
			"cnf":    map[string]any{"jkt": jkt},
		},
	})

	var logBuf bytes.Buffer
	capturingLogger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dv := dpop.NewVerifier(dpop.Config{}) // Opportunistic — enforces on bound tokens
	cfg := MiddlewareConfig{
		Validator: newValidator(t, j),
		Logger:    capturingLogger,
		DPoP:      dv,
	}

	req := httptest.NewRequest(http.MethodPost, "/tools/call", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	// Deliberately no DPoP header — triggers "bound token presented without a
	// dpop proof" rejection, which flows through writeAuthError and is logged.

	rec := httptest.NewRecorder()
	cfg.Middleware()(okHandlerFunc).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (body: %s)", rec.Code, rec.Body)
	}

	logged := logBuf.String()
	if logged == "" {
		t.Fatal("expected at least one log line from writeAuthError, got empty buffer")
	}

	// The bearer token is a JWT with three base64url parts. Logging any whole
	// section of it (or the raw string) would expose the token to log consumers.
	if strings.Contains(logged, tok) {
		t.Errorf("slog output contains the bearer token: %s", logged)
	}

	// The ath preimage is the base64url SHA-256 of the bearer token. Logging it
	// would allow reconstruction of a valid ath claim for a replayed proof.
	athPreimage := dpopAth(tok)
	if strings.Contains(logged, athPreimage) {
		t.Errorf("slog output contains the ath preimage (base64url SHA-256 of token): %s", logged)
	}
}
