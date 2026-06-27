package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	auth "github.com/polyglotdev/mcp-auth-go"
)

// newKey generates a fresh ES256 JWK (private) for use in proof construction.
func newKey(t *testing.T) jwk.Key {
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

// jktOf returns the base64url-encoded SHA-256 JWK thumbprint of the public
// half of k (RFC 7638).
func jktOf(t *testing.T, k jwk.Key) string {
	t.Helper()
	pub, _ := k.PublicKey()
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// mintProof builds a compact JWS proof signed with ES256 key k. The caller
// supplies the payload claims map and the typ header value; mutators tweak
// these for failure cases.
func mintProof(t *testing.T, k jwk.Key, claims map[string]any, typ string) string {
	t.Helper()
	pub, _ := k.PublicKey()
	payload, _ := json.Marshal(claims)
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.TypeKey, typ)
	_ = hdr.Set(jws.JWKKey, pub)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, k, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// athOf returns the base64url-no-pad SHA-256 of token, matching the ath claim
// the server computes (RFC 9449 §4.2).
func athOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// minimalVerifier returns a *Verifier configured for white-box proof tests:
// ES256 only, 60s leeway, nop replay cache, clock pinned to now.
func minimalVerifier(now time.Time) *Verifier {
	return &Verifier{
		iatLeeway: 60 * time.Second,
		replay:    NewNopReplayCache(),
		algAllow:  map[jwa.SignatureAlgorithm]struct{}{jwa.ES256: {}},
		now:       func() time.Time { return now },
	}
}

// TestCheckProofHappyPath verifies that a well-formed proof is accepted.
func TestCheckProofHappyPath(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKey(t)
	tokenStr := "the-access-token"
	v := minimalVerifier(now)
	in := Input{
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: tokenStr,
		BoundJKT:    jktOf(t, k),
	}
	proof := mintProof(t, k, map[string]any{
		"jti": "id1",
		"htm": "POST",
		"htu": "https://mcp.example/tools/call",
		"iat": now.Unix(),
		"ath": athOf(tokenStr),
	}, "dpop+jwt")

	if err := v.checkProof(proof, in, now); err != nil {
		t.Fatalf("happy path rejected: %v", err)
	}
}

// TestCheckProofHTUQueryAndFragmentIgnored verifies that htu comparison strips
// the query string and fragment (RFC 9449 §4.3(9)).
func TestCheckProofHTUQueryAndFragmentIgnored(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKey(t)
	tokenStr := "tok"
	v := minimalVerifier(now)
	in := Input{
		Method:      "GET",
		URL:         "https://mcp.example/res",
		AccessToken: tokenStr,
		BoundJKT:    jktOf(t, k),
	}

	for _, htu := range []string{
		"https://mcp.example/res?foo=bar",
		"https://mcp.example/res#section",
		"https://mcp.example/res?a=1#b",
	} {
		proof := mintProof(t, k, map[string]any{
			"jti": "id-" + htu,
			"htm": "GET",
			"htu": htu,
			"iat": now.Unix(),
			"ath": athOf(tokenStr),
		}, "dpop+jwt")
		if err := v.checkProof(proof, in, now); err != nil {
			t.Errorf("htu %q should pass (query/frag stripped): %v", htu, err)
		}
	}
}

// TestCheckProofFailures is a table of every §4.3 rejection case; each row
// asserts errors.Is(err, auth.ErrInvalidDPoPProof).
func TestCheckProofFailures(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKey(t)
	tokenStr := "the-access-token"

	goodClaims := func() map[string]any {
		return map[string]any{
			"jti": "id1",
			"htm": "POST",
			"htu": "https://mcp.example/tools/call",
			"iat": now.Unix(),
			"ath": athOf(tokenStr),
		}
	}
	goodIn := func() Input {
		return Input{
			Method:      "POST",
			URL:         "https://mcp.example/tools/call",
			AccessToken: tokenStr,
			BoundJKT:    jktOf(t, k),
		}
	}

	tests := []struct {
		name  string
		proof func() string
		in    func() Input
	}{
		{
			// §4.3(2): malformed compact JWS
			name: "tampered signature",
			proof: func() string {
				p := mintProof(t, k, goodClaims(), "dpop+jwt")
				// flip the last byte of the base64 signature segment
				b := []byte(p)
				b[len(b)-1] ^= 0x01
				return string(b)
			},
			in: goodIn,
		},
		{
			// §4.3(4): typ must be "dpop+jwt"
			name: "wrong typ",
			proof: func() string {
				return mintProof(t, k, goodClaims(), "JWT")
			},
			in: goodIn,
		},
		{
			// §4.3(5): algorithm must be asymmetric; HS256 is symmetric
			name: "alg HS256",
			proof: func() string {
				hk, _ := jwk.FromRaw([]byte("0123456789abcdef0123456789abcdef"))
				payload, _ := json.Marshal(goodClaims())
				pub, _ := k.PublicKey()
				hdr := jws.NewHeaders()
				_ = hdr.Set(jws.TypeKey, "dpop+jwt")
				_ = hdr.Set(jws.JWKKey, pub)
				signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256, hk, jws.WithProtectedHeaders(hdr)))
				if err != nil {
					t.Fatal(err)
				}
				return string(signed)
			},
			in: goodIn,
		},
		{
			// §4.3(5): alg=none must be rejected
			name: "alg none",
			proof: func() string {
				// jws.Sign refuses NoSignature, so hand-assemble the compact form.
				pub, _ := k.PublicKey()
				pubJSON, _ := json.Marshal(pub)
				hdrMap := map[string]any{
					"typ": "dpop+jwt",
					"alg": "none",
					"jwk": json.RawMessage(pubJSON),
				}
				hdrJSON, _ := json.Marshal(hdrMap)
				payload, _ := json.Marshal(goodClaims())
				hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
				payB64 := base64.RawURLEncoding.EncodeToString(payload)
				// compact: header.payload. (empty signature)
				return hdrB64 + "." + payB64 + "."
			},
			in: goodIn,
		},
		{
			// §4.3(6)/(7): embedded key must be the PUBLIC half
			name: "embedded private key",
			proof: func() string {
				payload, _ := json.Marshal(goodClaims())
				hdr := jws.NewHeaders()
				_ = hdr.Set(jws.TypeKey, "dpop+jwt")
				_ = hdr.Set(jws.JWKKey, k) // k is the private key, not pub
				signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, k, jws.WithProtectedHeaders(hdr)))
				if err != nil {
					t.Fatal(err)
				}
				return string(signed)
			},
			in: goodIn,
		},
		{
			// §4.3(3): jti is required
			name: "missing jti",
			proof: func() string {
				c := goodClaims()
				delete(c, "jti")
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(3): htm is required
			name: "missing htm",
			proof: func() string {
				c := goodClaims()
				delete(c, "htm")
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(3): htu is required
			name: "missing htu",
			proof: func() string {
				c := goodClaims()
				delete(c, "htu")
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(3): iat is required (zero value after unmarshal means absent)
			name: "missing iat",
			proof: func() string {
				c := goodClaims()
				delete(c, "iat")
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §7: ath is required for resource-server presentations
			name: "missing ath",
			proof: func() string {
				c := goodClaims()
				delete(c, "ath")
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(8): htm must match the request method
			name: "htm wrong method",
			proof: func() string {
				c := goodClaims()
				c["htm"] = "GET"
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(9): htu authority mismatch must reject even if path matches
			name: "htu wrong authority",
			proof: func() string {
				c := goodClaims()
				c["htu"] = "https://evil.example/tools/call"
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(11): iat too old (beyond -leeway)
			name: "iat too old",
			proof: func() string {
				c := goodClaims()
				c["iat"] = now.Add(-61 * time.Second).Unix()
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(11): iat in the future (beyond +leeway)
			name: "iat too far in future",
			proof: func() string {
				c := goodClaims()
				c["iat"] = now.Add(61 * time.Second).Unix()
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(12) / §7: ath must be the hash of THIS token
			name: "ath for different token",
			proof: func() string {
				c := goodClaims()
				c["ath"] = athOf("some-other-token")
				return mintProof(t, k, c, "dpop+jwt")
			},
			in: goodIn,
		},
		{
			// §4.3(12) / §6.1: embedded key's thumbprint must match BoundJKT
			name: "thumbprint mismatch (different key)",
			proof: func() string {
				// proof signed by k2, but BoundJKT is from k
				k2 := newKey(t)
				return mintProof(t, k2, goodClaims(), "dpop+jwt")
			},
			in: goodIn,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := minimalVerifier(now)
			err := v.checkProof(tc.proof(), tc.in(), now)
			if !errors.Is(err, auth.ErrInvalidDPoPProof) {
				t.Fatalf("want ErrInvalidDPoPProof, got %v", err)
			}
		})
	}
}

// TestCheckProofReplay verifies that a valid proof is accepted on first
// presentation and rejected on the second (replay), and that the same jti
// with a different htu is not a replay (per §11.1).
func TestCheckProofReplay(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKey(t)
	tokenStr := "the-access-token"

	rc := NewMemoryReplayCache(func() time.Time { return now })
	v := &Verifier{
		iatLeeway: 60 * time.Second,
		replay:    rc,
		algAllow:  map[jwa.SignatureAlgorithm]struct{}{jwa.ES256: {}},
		now:       func() time.Time { return now },
	}
	in := Input{
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: tokenStr,
		BoundJKT:    jktOf(t, k),
	}
	proof := mintProof(t, k, map[string]any{
		"jti": "replay-id",
		"htm": "POST",
		"htu": "https://mcp.example/tools/call",
		"iat": now.Unix(),
		"ath": athOf(tokenStr),
	}, "dpop+jwt")

	// First presentation: accept.
	if err := v.checkProof(proof, in, now); err != nil {
		t.Fatalf("first presentation rejected: %v", err)
	}
	// Second presentation with same jti+htu: replay.
	if err := v.checkProof(proof, in, now); !errors.Is(err, auth.ErrInvalidDPoPProof) {
		t.Fatalf("replay: want ErrInvalidDPoPProof, got %v", err)
	}
	// Same jti, different htu: a distinct entry, not a replay.
	in2 := in
	in2.URL = "https://mcp.example/other"
	proof2 := mintProof(t, k, map[string]any{
		"jti": "replay-id",
		"htm": "POST",
		"htu": "https://mcp.example/other",
		"iat": now.Unix(),
		"ath": athOf(tokenStr),
	}, "dpop+jwt")
	if err := v.checkProof(proof2, in2, now); err != nil {
		t.Fatalf("same jti, different htu should be allowed: %v", err)
	}
}

// TestCheckProofNonce tables the §4.3(10)/§11.3 nonce check on a nonce-configured
// verifier. Rows are pure data: the nonce value placed in the proof and the
// expected outcome. The valid/stale/forged variants are precomputed as locals.
func TestCheckProofNonce(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKey(t)
	tokenStr := "the-access-token"
	ns, err := NewSignedNonce(testNonceSecret(), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	v := minimalVerifier(now)
	v.nonce = ns
	in := Input{
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: tokenStr,
		BoundJKT:    jktOf(t, k),
	}

	valid := ns.Issue(now)
	stale := ns.Issue(now.Add(-2 * time.Minute)) // issued before the 1m lifetime
	forged := base64.RawURLEncoding.EncodeToString(make([]byte, 56))

	tests := []struct {
		name  string
		nonce string
		want  error // nil = accepted
	}{
		{name: "valid nonce", nonce: valid, want: nil},
		{name: "missing nonce", nonce: "", want: auth.ErrUseDPoPNonce},
		{name: "stale nonce", nonce: stale, want: auth.ErrUseDPoPNonce},
		{name: "forged nonce", nonce: forged, want: auth.ErrUseDPoPNonce},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{
				"jti": tc.name,
				"htm": "POST",
				"htu": "https://mcp.example/tools/call",
				"iat": now.Unix(),
				"ath": athOf(tokenStr),
			}
			if tc.nonce != "" {
				claims["nonce"] = tc.nonce
			}
			err := v.checkProof(mintProof(t, k, claims, "dpop+jwt"), in, now)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// TestCheckProofNonceIgnoredWhenUnconfigured proves a nonce-nil verifier does
// not demand a nonce (slice-#1 behavior preserved; §4.3(10) is conditional on
// the server having provided one).
func TestCheckProofNonceIgnoredWhenUnconfigured(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKey(t)
	tokenStr := "tok"
	v := minimalVerifier(now) // nonce nil
	in := Input{
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: tokenStr,
		BoundJKT:    jktOf(t, k),
	}
	proof := mintProof(t, k, map[string]any{
		"jti": "no-nonce",
		"htm": "POST",
		"htu": "https://mcp.example/tools/call",
		"iat": now.Unix(),
		"ath": athOf(tokenStr),
	}, "dpop+jwt") // no nonce claim
	if err := v.checkProof(proof, in, now); err != nil {
		t.Fatalf("nonce-nil verifier must ignore a missing nonce: %v", err)
	}
}

// TestCheckProofNonceNotRecordedBeforeReplay proves a nonce-less proof is
// re-challenged WITHOUT being recorded in the replay cache: a later valid proof
// reusing the same jti (now with a fresh nonce) still passes, so the challenge
// round-trip does not poison the cache against a client that reuses a jti.
func TestCheckProofNonceNotRecordedBeforeReplay(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKey(t)
	tokenStr := "tok"
	ns, err := NewSignedNonce(testNonceSecret(), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	v := &Verifier{
		iatLeeway: 60 * time.Second,
		replay:    NewMemoryReplayCache(func() time.Time { return now }),
		algAllow:  map[jwa.SignatureAlgorithm]struct{}{jwa.ES256: {}},
		now:       func() time.Time { return now },
		nonce:     ns,
	}
	in := Input{
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: tokenStr,
		BoundJKT:    jktOf(t, k),
	}
	base := map[string]any{
		"jti": "reuse",
		"htm": "POST",
		"htu": "https://mcp.example/tools/call",
		"iat": now.Unix(),
		"ath": athOf(tokenStr),
	}

	// No nonce: re-challenged, and NOT recorded in the replay cache.
	if err := v.checkProof(mintProof(t, k, base, "dpop+jwt"), in, now); !errors.Is(err, auth.ErrUseDPoPNonce) {
		t.Fatalf("no-nonce: want ErrUseDPoPNonce, got %v", err)
	}
	// Same jti, now with a fresh nonce: must pass (not a false replay).
	base["nonce"] = ns.Issue(now)
	if err := v.checkProof(mintProof(t, k, base, "dpop+jwt"), in, now); err != nil {
		t.Fatalf("jti reuse after a nonce challenge must pass: %v", err)
	}
}

// TestNonceRejectionLeaksNoSecret proves a nonce rejection wraps only a constant
// reason: neither the access token, its ath preimage hash, nor the (forged)
// nonce value reaches err.Error() (auth.Error.Error() renders the Cause into
// logs, so a non-constant cause would leak).
func TestNonceRejectionLeaksNoSecret(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newKey(t)
	tokenStr := "super-secret-access-token"
	ns, err := NewSignedNonce(testNonceSecret(), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	v := minimalVerifier(now)
	v.nonce = ns
	in := Input{
		Method:      "POST",
		URL:         "https://mcp.example/tools/call",
		AccessToken: tokenStr,
		BoundJKT:    jktOf(t, k),
	}
	forged := base64.RawURLEncoding.EncodeToString(make([]byte, 56))
	proof := mintProof(t, k, map[string]any{
		"jti":   "leak",
		"htm":   "POST",
		"htu":   "https://mcp.example/tools/call",
		"iat":   now.Unix(),
		"ath":   athOf(tokenStr),
		"nonce": forged,
	}, "dpop+jwt")

	gotErr := v.checkProof(proof, in, now)
	if !errors.Is(gotErr, auth.ErrUseDPoPNonce) {
		t.Fatalf("want ErrUseDPoPNonce, got %v", gotErr)
	}

	tests := []struct {
		name   string
		secret string
	}{
		{name: "access token", secret: tokenStr},
		{name: "forged nonce", secret: forged},
		{name: "ath preimage hash", secret: athOf(tokenStr)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(gotErr.Error(), tc.secret) {
				t.Errorf("error leaked the %s: %q", tc.name, gotErr.Error())
			}
		})
	}
}
