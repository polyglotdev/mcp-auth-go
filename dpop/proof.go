package dpop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	auth "github.com/polyglotdev/mcp-auth-go"
)

// proofClaims is the subset of the DPoP proof payload the resource server
// checks (RFC 9449 §4.2 / §7).
type proofClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath"`
	Nonce string `json:"nonce"`
}

// checkProof runs the RFC 9449 §4.3 receiver checks for a single proof
// presented alongside an access token. It returns nil on success or
// ErrInvalidDPoPProof wrapping a CONSTANT reason string (never a token value
// or computed hash) for log-only consumption.
//
// Security ordering: the JWS signature is verified (step 6 below) BEFORE any
// claim is trusted; replay is checked LAST so only otherwise-valid proofs
// enter the cache.
func (v *Verifier) checkProof(proof string, in Input, now time.Time) error {
	reject := func(reason string) error {
		return auth.ErrInvalidDPoPProof.With(errors.New(reason))
	}

	// §4.3(2): the proof must be a well-formed compact JWS.
	msg, err := jws.Parse([]byte(proof))
	if err != nil {
		return reject("malformed dpop proof")
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return reject("dpop proof must carry exactly one signature")
	}
	hdr := sigs[0].ProtectedHeaders()

	// §4.3(4): the typ header must be "dpop+jwt" (case-sensitive).
	if hdr.Type() != "dpop+jwt" {
		return reject("dpop proof typ is not dpop+jwt")
	}

	// §4.3(5): only asymmetric algorithms; none and symmetric rejected.
	alg := hdr.Algorithm()
	if !v.algAllowed(alg) {
		return reject("dpop proof alg not allowed")
	}

	// §4.3(6): the proof must embed a public key in the jwk header.
	key := hdr.JWK()
	if key == nil {
		return reject("dpop proof missing embedded jwk")
	}

	// §4.3(7): the embedded key must be public. jwk.IsPrivateKey returns an
	// error for symmetric keys; fail closed in that case too.
	if priv, perr := jwk.IsPrivateKey(key); perr != nil || priv {
		return reject("dpop proof jwk must be a public key")
	}

	// §4.3(6): verify the signature using the embedded key. This MUST happen
	// before any claim is trusted.
	if _, verr := jws.Verify([]byte(proof), jws.WithKey(alg, key)); verr != nil {
		return reject("dpop proof signature invalid")
	}

	// §4.3(3): unmarshal the verified payload.
	var c proofClaims
	if err := json.Unmarshal(msg.Payload(), &c); err != nil {
		return reject("dpop proof payload invalid")
	}

	// §4.3(3) / §7: all required claims must be present. iat==0 means absent
	// because a valid Unix timestamp is never zero in practice.
	if c.JTI == "" || c.HTM == "" || c.HTU == "" || c.IAT == 0 || c.ATH == "" {
		return reject("dpop proof missing a required claim")
	}

	// §4.3(8): htm must exactly match the HTTP method of the request.
	if c.HTM != in.Method {
		return reject("dpop htm mismatch")
	}

	// §4.3(9): htu must match after stripping query and fragment.
	if stripURL(c.HTU) != stripURL(in.URL) {
		return reject("dpop htu mismatch")
	}

	// §4.3(11) / §11.1: proof must be fresh within the configured leeway.
	iat := time.Unix(c.IAT, 0)
	if iat.Before(now.Add(-v.iatLeeway)) || iat.After(now.Add(v.iatLeeway)) {
		return reject("dpop iat outside acceptable window")
	}

	// §4.3(12) first bullet / §7: ath must be the base64url SHA-256 of the
	// access token. The token and the preimage are secrets; the reason string
	// is a constant so they never appear in logs.
	if c.ATH != ath(in.AccessToken) {
		return reject("dpop ath mismatch")
	}

	// §4.3(12) second bullet / §6.1: the embedded key's thumbprint must match
	// the token's cnf.jkt binding.
	tp, terr := key.Thumbprint(crypto.SHA256)
	if terr != nil {
		return reject("dpop thumbprint error")
	}
	if base64.RawURLEncoding.EncodeToString(tp) != in.BoundJKT {
		return reject("dpop key does not match token binding")
	}

	// §4.3(10) / §11.3: when a nonce is required, the proof must carry a fresh,
	// server-issued nonce. Placed after the binding is proven (never hand a fresh
	// nonce to a forged proof) and before replay (a nonce-less proof is not
	// recorded; the client retries with a new jti). Missing, stale, and forged
	// all re-challenge. The reason is a constant -- the nonce and token never
	// reach logs.
	if v.nonce != nil && (c.Nonce == "" || !v.nonce.Validate(c.Nonce, now)) {
		return auth.ErrUseDPoPNonce.With(errors.New("dpop proof missing or stale nonce"))
	}

	// §11.1: replay check is last, so only otherwise-valid proofs are recorded.
	if v.replay.SeenBefore(c.JTI, stripURL(c.HTU), iat.Add(v.iatLeeway)) {
		return reject("dpop proof replayed")
	}
	return nil
}

// ath returns the base64url-no-pad SHA-256 of the access token (RFC 9449
// §4.2 / RFC 7515 §2). The input is a bearer token — never log it or the
// return value.
func ath(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// stripURL drops the query and fragment for htu comparison (RFC 9449 §4.3(9)).
// Both sides of the comparison pass through this function, so url.Parse's
// re-encoding is applied symmetrically; an unparseable URL (the rare url.Parse
// error) is returned raw and simply won't match a well-formed one — fail closed.
func stripURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
