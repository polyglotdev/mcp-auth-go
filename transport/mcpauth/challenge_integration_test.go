package mcpauth_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/polyglotdev/mcp-auth-go/dpop"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
	"github.com/polyglotdev/mcp-auth-go/transport/mcpauth"
)

// newDPoPKey generates a fresh ES256 JWK for DPoP proof signing.
func newDPoPKey(t *testing.T) jwk.Key {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.AlgorithmKey, jwa.ES256)
	return key
}

// thumbprintOf returns the base64url RFC 7638 SHA-256 thumbprint of key's public
// half -- the value bound into a token's cnf.jkt.
func thumbprintOf(t *testing.T, key jwk.Key) string {
	t.Helper()
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// athOf is base64url(sha256(token)) -- the proof's ath claim.
func athOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// mintProof signs a DPoP proof (typ=dpop+jwt, ES256) embedding key's public half
// and the given claims. The per-case data (jti/nonce/iat) lives at the call site.
func mintProof(t *testing.T, key jwk.Key, claims map[string]any) string {
	t.Helper()
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.TypeKey, "dpop+jwt")
	_ = hdr.Set(jws.JWKKey, pub)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// serve sends one request (bearer + optional DPoP proof) through h and returns
// the recorder.
func serve(t *testing.T, h http.Handler, method, path, token, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestRequireBearerTokenDPoPSchemeChallenge proves a DPoP enforcement failure on
// the SDK transport is answered with a DPoP-scheme WWW-Authenticate (RFC 9449
// §7.1) -- not the SDK's hard-coded Bearer scheme -- and carries the RFC 9728
// resource_metadata pointer only when configured.
func TestRequireBearerTokenDPoPSchemeChallenge(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	boundTok := j.Mint(t, jwkstest.ClaimSet{Subject: "u", Private: map[string]any{"cnf": map[string]any{"jkt": "deadbeef"}}})

	tests := []struct {
		name        string
		resourceURL string
		wantMeta    bool
	}{
		{name: "no resource metadata", resourceURL: "", wantMeta: false},
		{name: "with resource metadata", resourceURL: "https://mcp.example/.well-known/oauth-protected-resource", wantMeta: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mcpauth.RequireBearerToken(v, &mcpauth.Options{
				DPoP:                dpop.NewVerifier(dpop.Config{}),
				ResourceMetadataURL: tt.resourceURL,
			})(okHandler())
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Authorization", "Bearer "+boundTok) // bound token, NO DPoP header
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want 401 (body: %s)", rec.Code, rec.Body)
			}
			wa := rec.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(wa, "DPoP ") || !strings.Contains(wa, `error="invalid_dpop_proof"`) {
				t.Fatalf("challenge = %q; want DPoP scheme + invalid_dpop_proof", wa)
			}
			if gotMeta := strings.Contains(wa, "resource_metadata="); gotMeta != tt.wantMeta {
				t.Errorf("resource_metadata present = %v, want %v (%q)", gotMeta, tt.wantMeta, wa)
			}
		})
	}
}

// TestRequireBearerTokenNonceRoundTrip proves the full RFC 9449 §9 nonce dance on
// the SDK transport: a valid but nonce-less proof is re-challenged with a
// use_dpop_nonce 401 carrying a DPoP-Nonce, and a retry embedding that nonce
// succeeds and rotates a fresh nonce onto the 200 (§8.2).
func TestRequireBearerTokenNonceRoundTrip(t *testing.T) {
	const baseURL, method, path = "https://mcp.example.com", http.MethodPost, "/mcp"
	htu := baseURL + path

	j := jwkstest.New(t)
	key := newDPoPKey(t)
	tok := j.Mint(t, jwkstest.ClaimSet{Subject: "alice", Private: map[string]any{"cnf": map[string]any{"jkt": thumbprintOf(t, key)}}})
	ath := athOf(tok)

	ns, err := dpop.NewSignedNonce(make([]byte, 32), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	v := newValidator(t, j)
	dv := dpop.NewVerifier(dpop.Config{Nonce: ns, ReplayCache: dpop.NewNopReplayCache()})
	h := mcpauth.RequireBearerToken(v, &mcpauth.Options{DPoP: dv, BaseURL: baseURL})(okHandler())

	// Leg 1: a fully valid proof with NO nonce -> 401 + DPoP use_dpop_nonce + DPoP-Nonce.
	proof1 := mintProof(t, key, map[string]any{"jti": "n1", "htm": method, "htu": htu, "iat": time.Now().Unix(), "ath": ath})
	rec1 := serve(t, h, method, path, tok, proof1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("leg 1 status = %d; want 401 (body: %s)", rec1.Code, rec1.Body)
	}
	if wa := rec1.Header().Get("WWW-Authenticate"); !strings.HasPrefix(wa, "DPoP ") || !strings.Contains(wa, `error="use_dpop_nonce"`) {
		t.Fatalf("leg 1 challenge = %q; want DPoP use_dpop_nonce", wa)
	}
	issued := rec1.Header().Get("DPoP-Nonce")
	if issued == "" {
		t.Fatal("leg 1 must set a non-empty DPoP-Nonce")
	}

	// Leg 2: retry with the issued nonce (fresh iat, new jti) -> 200 + rotated nonce + no-store.
	proof2 := mintProof(t, key, map[string]any{"jti": "n2", "htm": method, "htu": htu, "iat": time.Now().Unix(), "ath": ath, "nonce": issued})
	rec2 := serve(t, h, method, path, tok, proof2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("leg 2 status = %d; want 200 (body: %s)", rec2.Code, rec2.Body)
	}
	if rec2.Header().Get("DPoP-Nonce") == "" {
		t.Fatal("leg 2 success must rotate a fresh DPoP-Nonce")
	}
	if got := rec2.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("leg 2 Cache-Control = %q; want no-store (okHandler sets none)", got)
	}
}

// TestRequireBearerTokenStreamingFlush is the headline streaming test: a valid
// bound proof reaches a handler that flushes via http.ResponseController. The
// flush must reach the underlying writer through challengeWriter.Unwrap (proven
// by rec.Flushed), and the rotation DPoP-Nonce must not clobber the handler's
// own Cache-Control (the SDK's SSE path sets no-cache, no-transform).
func TestRequireBearerTokenStreamingFlush(t *testing.T) {
	const baseURL, method, path = "https://mcp.example.com", http.MethodPost, "/mcp"
	htu := baseURL + path

	j := jwkstest.New(t)
	key := newDPoPKey(t)
	tok := j.Mint(t, jwkstest.ClaimSet{Subject: "alice", Private: map[string]any{"cnf": map[string]any{"jkt": thumbprintOf(t, key)}}})
	ath := athOf(tok)

	ns, err := dpop.NewSignedNonce(make([]byte, 32), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	v := newValidator(t, j)
	dv := dpop.NewVerifier(dpop.Config{Nonce: ns, ReplayCache: dpop.NewNopReplayCache()})

	flushed := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-transform") // mimic the SDK's SSE path
		rc := http.NewResponseController(w)
		_, _ = w.Write([]byte("data: hi\n\n"))
		flushed = rc.Flush() == nil
	})
	h := mcpauth.RequireBearerToken(v, &mcpauth.Options{DPoP: dv, BaseURL: baseURL})(inner)

	proof := mintProof(t, key, map[string]any{"jti": "s1", "htm": method, "htu": htu, "iat": time.Now().Unix(), "ath": ath, "nonce": ns.Issue(time.Now())})
	rec := serve(t, h, method, path, tok, proof)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body: %s)", rec.Code, rec.Body)
	}
	if !flushed || !rec.Flushed {
		t.Fatalf("flush did not reach the underlying writer through the wrapper (flushed=%v, rec.Flushed=%v)", flushed, rec.Flushed)
	}
	if rec.Header().Get("DPoP-Nonce") == "" {
		t.Fatal("streamed 200 must carry a rotation DPoP-Nonce")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache, no-transform" {
		t.Errorf("Cache-Control = %q; rotation must NOT clobber the handler's value", got)
	}
}

// TestRequireBearerTokenNonDPoPEmitsNoNonce proves the wrapper is installed only
// when DPoP is configured: neither nil options nor options without a DPoP
// verifier ever emit a DPoP-Nonce or a DPoP-scheme challenge (spec E7).
func TestRequireBearerTokenNonDPoPEmitsNoNonce(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	tests := []struct {
		name string
		opts *mcpauth.Options
	}{
		{name: "nil options", opts: nil},
		{name: "options without DPoP", opts: &mcpauth.Options{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mcpauth.RequireBearerToken(v, tt.opts)(okHandler())
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil) // no bearer -> 401
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want 401 (no bearer)", rec.Code)
			}
			if rec.Header().Get("DPoP-Nonce") != "" {
				t.Error("non-DPoP middleware must never emit DPoP-Nonce")
			}
			if wa := rec.Header().Get("WWW-Authenticate"); strings.HasPrefix(wa, "DPoP ") {
				t.Errorf("non-DPoP challenge = %q; must not be DPoP-schemed", wa)
			}
		})
	}
}

// TestRequireBearerTokenDPoPWithoutNonceEmitsNoNonce proves a DPoP verifier with
// no NonceSource answers a binding failure with a DPoP invalid_dpop_proof
// challenge but never a DPoP-Nonce (nothing to issue).
func TestRequireBearerTokenDPoPWithoutNonceEmitsNoNonce(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)
	boundTok := j.Mint(t, jwkstest.ClaimSet{Subject: "u", Private: map[string]any{"cnf": map[string]any{"jkt": "deadbeef"}}})

	h := mcpauth.RequireBearerToken(v, &mcpauth.Options{DPoP: dpop.NewVerifier(dpop.Config{})})(okHandler())
	rec := serve(t, h, http.MethodPost, "/mcp", boundTok, "") // bound token, no proof -> invalid_dpop_proof

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(wa, "DPoP ") || !strings.Contains(wa, `error="invalid_dpop_proof"`) {
		t.Fatalf("challenge = %q; want DPoP invalid_dpop_proof", wa)
	}
	if rec.Header().Get("DPoP-Nonce") != "" {
		t.Error("DPoP-without-nonce must not emit DPoP-Nonce")
	}
}

// TestRequireBearerTokenScope403StaysBearer proves a scope shortfall (the SDK's
// own check, after DPoP passes) keeps the RFC 6750 Bearer challenge -- the
// wrapper rewrites only DPoP failures, never the scope 403.
func TestRequireBearerTokenScope403StaysBearer(t *testing.T) {
	const baseURL, method, path = "https://mcp.example.com", http.MethodPost, "/mcp"
	htu := baseURL + path

	j := jwkstest.New(t)
	key := newDPoPKey(t)
	tok := j.Mint(t, jwkstest.ClaimSet{Subject: "alice", Private: map[string]any{"cnf": map[string]any{"jkt": thumbprintOf(t, key)}}}) // no scope claim
	ath := athOf(tok)

	v := newValidator(t, j)
	dv := dpop.NewVerifier(dpop.Config{ReplayCache: dpop.NewNopReplayCache()})
	h := mcpauth.RequireBearerToken(v, &mcpauth.Options{DPoP: dv, BaseURL: baseURL, Scopes: []string{"mcp:admin"}})(okHandler())

	proof := mintProof(t, key, map[string]any{"jti": "sc1", "htm": method, "htu": htu, "iat": time.Now().Unix(), "ath": ath})
	rec := serve(t, h, method, path, tok, proof)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403 (insufficient scope; body: %s)", rec.Code, rec.Body)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); strings.HasPrefix(wa, "DPoP ") {
		t.Errorf("scope 403 challenge = %q; must stay Bearer (DPoP passed)", wa)
	}
}
