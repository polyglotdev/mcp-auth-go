// Package jwkstest provides an in-memory RSA signing key and an httptest
// server that serves the matching JWKS document, so tests across the module
// can mint JWTs that validate against a real Validator.
//
// It imports only jwx and the standard library -- never the auth package --
// so both black-box and white-box test suites can use it without import
// cycles.
package jwkstest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// JWKS bundles an RSA signing key and an httptest server that serves the
// matching JWKS document. Construct it with New.
type JWKS struct {
	server   *httptest.Server
	privKey  jwk.Key
	issuer   string
	audience string
}

// New spins up an RSA key pair and an httptest server serving the JWKS
// document at /jwks. The server is closed via t.Cleanup.
func New(t testing.TB) *JWKS {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}

	priv, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	if err := priv.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := priv.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &JWKS{
		server:   srv,
		privKey:  priv,
		issuer:   "https://test-issuer.example.com/oauth2/aus123",
		audience: "https://mcp.test.example.com",
	}
}

// URL is the absolute URL clients use to fetch the JWKS document.
func (j *JWKS) URL() string { return j.server.URL + "/jwks" }

// Issuer is the default iss this JWKS mints tokens for.
func (j *JWKS) Issuer() string { return j.issuer }

// Audience is the default aud this JWKS mints tokens for.
func (j *JWKS) Audience() string { return j.audience }

// ClaimSet is the convenience builder for Mint inputs. Zero fields take
// sensible defaults: Issuer/Audience fall back to the JWKS values, and
// NotAfter defaults to one hour.
type ClaimSet struct {
	Subject   string
	Email     string
	Issuer    string         // overrides the JWKS issuer when set
	Audience  string         // overrides the JWKS audience when set
	NotAfter  time.Duration  // exp - now; defaults to 1h
	NotBefore time.Duration  // nbf - now; defaults to 0 (unset)
	Private   map[string]any // extra claims (backend, scope, etc.)
}

// Mint returns a signed JWT matching this JWKS. Use it to construct
// happy-path and adversarial tokens for validator and middleware tests.
func (j *JWKS) Mint(t testing.TB, cs ClaimSet) string {
	t.Helper()
	return j.signWith(t, cs, j.privKey)
}

// MintWithWrongKey returns a structurally valid JWT signed by an unrelated
// key, so it fails signature verification against this JWKS. Use it to prove
// the JWKS lookup actually gates signature acceptance.
func (j *JWKS) MintWithWrongKey(t testing.TB, cs ClaimSet) string {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate foreign rsa: %v", err)
	}
	other, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw (foreign): %v", err)
	}
	if err := other.Set(jwk.KeyIDKey, "foreign-key"); err != nil {
		t.Fatalf("set foreign kid: %v", err)
	}
	if err := other.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set foreign alg: %v", err)
	}
	return j.signWith(t, cs, other)
}

// signWith builds the token described by cs and signs it with key.
func (j *JWKS) signWith(t testing.TB, cs ClaimSet, key jwk.Key) string {
	t.Helper()
	if cs.NotAfter == 0 {
		cs.NotAfter = time.Hour
	}
	iss := j.issuer
	if cs.Issuer != "" {
		iss = cs.Issuer
	}
	aud := j.audience
	if cs.Audience != "" {
		aud = cs.Audience
	}

	now := time.Now()
	builder := jwt.NewBuilder().
		Issuer(iss).
		Audience([]string{aud}).
		Subject(cs.Subject).
		IssuedAt(now).
		Expiration(now.Add(cs.NotAfter))

	if cs.NotBefore != 0 {
		builder = builder.NotBefore(now.Add(cs.NotBefore))
	}
	if cs.Email != "" {
		builder = builder.Claim("email", cs.Email)
	}
	for k, v := range cs.Private {
		builder = builder.Claim(k, v)
	}

	tok, err := builder.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}
