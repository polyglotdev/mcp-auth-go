package dpop_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
)

// helpers for the black-box tests — they don't import package-internal
// symbols, so they duplicate only what's needed.

func newECKey(t *testing.T) jwk.Key {
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

func thumbprintOf(t *testing.T, k jwk.Key) string {
	t.Helper()
	pub, _ := k.PublicKey()
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

func athHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func buildProof(t *testing.T, k jwk.Key, claims map[string]any) string {
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

// TestEnforceTruthTable exercises the bound×proofs×mode matrix (spec M5).
func TestEnforceTruthTable(t *testing.T) {
	now := time.Unix(1000, 0)
	mk := func(mode dpop.Mode) *dpop.Verifier {
		return dpop.NewVerifier(dpop.Config{
			Mode:        mode,
			Now:         func() time.Time { return now },
			ReplayCache: dpop.NewNopReplayCache(),
		})
	}

	// Unbound + Opportunistic → pass (plain bearer).
	if err := mk(dpop.Opportunistic).Enforce(context.Background(), dpop.Input{}); err != nil {
		t.Fatalf("opportunistic unbound: %v", err)
	}

	// Unbound + Require → reject (§M5 / §E4).
	if err := mk(dpop.Require).Enforce(context.Background(), dpop.Input{}); !errors.Is(err, auth.ErrInvalidDPoPProof) {
		t.Fatalf("require unbound: want ErrInvalidDPoPProof, got %v", err)
	}

	// Bound + 0 proofs → reject (§7.2 downgrade, §E1).
	if err := mk(dpop.Opportunistic).Enforce(context.Background(), dpop.Input{BoundJKT: "x"}); !errors.Is(err, auth.ErrInvalidDPoPProof) {
		t.Fatalf("downgrade (0 proofs): want ErrInvalidDPoPProof, got %v", err)
	}

	// Bound + >1 proofs → reject (§E2).
	if err := mk(dpop.Opportunistic).Enforce(context.Background(), dpop.Input{
		BoundJKT: "x",
		Proofs:   []string{"a", "b"},
	}); !errors.Is(err, auth.ErrInvalidDPoPProof) {
		t.Fatalf(">1 proof: want ErrInvalidDPoPProof, got %v", err)
	}
}

// TestEnforceBoundHappyPath verifies that a valid bound token + matching proof
// is accepted end-to-end through the public Enforce method.
func TestEnforceBoundHappyPath(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newECKey(t)
	token := "access-token-abc"
	jkt := thumbprintOf(t, k)

	v := dpop.NewVerifier(dpop.Config{
		Now:         func() time.Time { return now },
		ReplayCache: dpop.NewNopReplayCache(),
	})
	proof := buildProof(t, k, map[string]any{
		"jti": "uniq-1",
		"htm": "POST",
		"htu": "https://mcp.example/tools/call",
		"iat": now.Unix(),
		"ath": athHash(token),
	})
	in := dpop.Input{
		Proofs:      []string{proof},
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: token,
		BoundJKT:    jkt,
	}
	if err := v.Enforce(context.Background(), in); err != nil {
		t.Fatalf("bound happy path: %v", err)
	}
}

// TestEnforceBoundTampered verifies that a proof with a wrong ath (wrong
// access-token hash) is rejected, proving Enforce routes through checkProof.
func TestEnforceBoundTampered(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newECKey(t)
	token := "access-token-abc"
	jkt := thumbprintOf(t, k)

	v := dpop.NewVerifier(dpop.Config{
		Now:         func() time.Time { return now },
		ReplayCache: dpop.NewNopReplayCache(),
	})
	proof := buildProof(t, k, map[string]any{
		"jti": "uniq-2",
		"htm": "POST",
		"htu": "https://mcp.example/tools/call",
		"iat": now.Unix(),
		"ath": athHash("wrong-token"), // deliberately wrong
	})
	in := dpop.Input{
		Proofs:      []string{proof},
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: token,
		BoundJKT:    jkt,
	}
	if err := v.Enforce(context.Background(), in); !errors.Is(err, auth.ErrInvalidDPoPProof) {
		t.Fatalf("tampered ath: want ErrInvalidDPoPProof, got %v", err)
	}
}

// TestNewVerifierDefaults verifies that a zero-value Config produces a usable
// Verifier (defaults filled in, no panic).
func TestNewVerifierDefaults(t *testing.T) {
	v := dpop.NewVerifier(dpop.Config{})
	if v == nil {
		t.Fatal("NewVerifier returned nil")
	}
	// Unbound + opportunistic (default mode) should pass without panic.
	if err := v.Enforce(context.Background(), dpop.Input{}); err != nil {
		t.Fatalf("zero-value config, unbound: %v", err)
	}
}

// TestNewVerifierAlgAllowFiltersSymmetric verifies that algSet drops symmetric
// algorithms even if the caller accidentally includes them in AlgAllow.
func TestNewVerifierAlgAllowFiltersSymmetric(t *testing.T) {
	now := time.Unix(1000, 0)
	// Ask for HS256 + ES256; the verifier must silently drop HS256.
	v := dpop.NewVerifier(dpop.Config{
		AlgAllow:    []jwa.SignatureAlgorithm{jwa.HS256, jwa.ES256},
		Now:         func() time.Time { return now },
		ReplayCache: dpop.NewNopReplayCache(),
	})

	// Build a proper ES256 proof → should be accepted.
	k := newECKey(t)
	token := "tok"
	proof := buildProof(t, k, map[string]any{
		"jti": "x",
		"htm": "GET",
		"htu": "https://example.com/r",
		"iat": now.Unix(),
		"ath": athHash(token),
	})
	in := dpop.Input{
		Proofs:      []string{proof},
		Method:      "GET",
		URL:         "https://example.com/r",
		AccessToken: token,
		BoundJKT:    thumbprintOf(t, k),
	}
	if err := v.Enforce(context.Background(), in); err != nil {
		t.Fatalf("ES256 with mixed AlgAllow: %v", err)
	}
}

// TestVerifierNonceConfigured verifies that a configured NonceSource flips
// NonceConfigured to true and makes IssueNonce mint, while the zero Config
// leaves both off (the opt-in contract both transports depend on).
func TestVerifierNonceConfigured(t *testing.T) {
	now := time.Unix(1000, 0)
	ns, err := dpop.NewSignedNonce(make([]byte, 32), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}

	tests := []struct {
		name           string
		cfg            dpop.Config
		wantConfigured bool
	}{
		{name: "with nonce source", cfg: dpop.Config{Nonce: ns}, wantConfigured: true},
		{name: "without nonce source", cfg: dpop.Config{}, wantConfigured: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := dpop.NewVerifier(tt.cfg)
			if got := v.NonceConfigured(); got != tt.wantConfigured {
				t.Errorf("NonceConfigured() = %v, want %v", got, tt.wantConfigured)
			}
			gotNonce := v.IssueNonce(now)
			if tt.wantConfigured && gotNonce == "" {
				t.Error("IssueNonce() = empty, want a minted nonce")
			}
			if !tt.wantConfigured && gotNonce != "" {
				t.Errorf("IssueNonce() = %q, want empty", gotNonce)
			}
		})
	}
}

// TestEnforceBoundNoProofWithNonceIsDowngrade proves the nonce step (inside
// checkProof) does not change Enforce's outer truth table: a bound token with
// ZERO proofs is still the §7.2 downgrade (ErrInvalidDPoPProof), never a
// use_dpop_nonce challenge -- the nonce demand only arises once a proof is
// actually presented.
func TestEnforceBoundNoProofWithNonceIsDowngrade(t *testing.T) {
	now := time.Unix(1000, 0)
	ns, err := dpop.NewSignedNonce(make([]byte, 32), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	v := dpop.NewVerifier(dpop.Config{
		Nonce:       ns,
		Now:         func() time.Time { return now },
		ReplayCache: dpop.NewNopReplayCache(),
	})
	err = v.Enforce(context.Background(), dpop.Input{BoundJKT: "x"}) // bound, zero proofs
	if !errors.Is(err, auth.ErrInvalidDPoPProof) {
		t.Fatalf("bound + 0 proofs: want ErrInvalidDPoPProof, got %v", err)
	}
	if errors.Is(err, auth.ErrUseDPoPNonce) {
		t.Fatal("bound + 0 proofs must NOT be a use_dpop_nonce challenge")
	}
}
