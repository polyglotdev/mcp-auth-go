package dpop

import (
	"context"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	auth "github.com/polyglotdev/mcp-auth-go"
)

// Mode selects the DPoP enforcement posture.
type Mode int

const (
	// Opportunistic enforces a proof only when the token is bound (has cnf.jkt);
	// unbound tokens pass through as plain bearer. The default.
	Opportunistic Mode = iota
	// Require mandates DPoP binding: an unbound token is rejected regardless of
	// what the client presents.
	Require
)

const defaultIATLeeway = 60 * time.Second

// defaultAlgs is the asymmetric allowlist used when Config.AlgAllow is empty.
// none and symmetric algorithms are never accepted (RFC 9449 §4.3(5)).
var defaultAlgs = []jwa.SignatureAlgorithm{
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.PS256, jwa.PS384, jwa.PS512,
	jwa.EdDSA,
}

// Config configures a Verifier. The zero value is valid: Opportunistic mode, a
// 60s iat window, and an in-memory replay cache.
type Config struct {
	// Mode selects Opportunistic (default) or Require posture.
	Mode Mode
	// IATLeeway is the symmetric acceptable window around a proof's iat claim.
	// Values below 1s fall back to the 60s default.
	IATLeeway time.Duration
	// ReplayCache provides jti single-use. nil ⇒ an in-memory default (enabled);
	// pass NewNopReplayCache() to disable (freshness-window-only protection).
	ReplayCache ReplayCache
	// AlgAllow narrows the accepted asymmetric algorithms; empty ⇒ defaultAlgs.
	// none and symmetric algorithms are never accepted regardless of this field.
	AlgAllow []jwa.SignatureAlgorithm
	// Nonce, when set, requires every enforced proof to carry a valid RS-issued
	// nonce (RFC 9449 §9). nil ⇒ no nonce demanded (the default). Use SignedNonce
	// for the stateless default. Supported on transport/http and on
	// transport/mcpauth (the latter via a response-wrapping middleware -- slice #3).
	Nonce NonceSource
	// Now is the clock, injected for tests; nil ⇒ time.Now.
	Now func() time.Time
}

// Verifier enforces RFC 9449 proof-of-possession. Construct with NewVerifier.
type Verifier struct {
	mode      Mode
	iatLeeway time.Duration
	replay    ReplayCache
	algAllow  map[jwa.SignatureAlgorithm]struct{}
	now       func() time.Time
	nonce     NonceSource
}

// NewVerifier builds a Verifier from cfg, filling defaults for every zero
// field. Now is resolved before the default ReplayCache so they share one
// clock when the caller provides no replay cache.
func NewVerifier(cfg Config) *Verifier {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	leeway := cfg.IATLeeway
	if leeway < time.Second {
		leeway = defaultIATLeeway
	}
	replay := cfg.ReplayCache
	if replay == nil {
		replay = NewMemoryReplayCache(now)
	}
	algs := cfg.AlgAllow
	if len(algs) == 0 {
		algs = defaultAlgs
	}
	return &Verifier{
		mode:      cfg.Mode,
		iatLeeway: leeway,
		replay:    replay,
		algAllow:  algSet(algs),
		now:       now,
		nonce:     cfg.Nonce,
	}
}

// algSet converts a slice of algorithms into a fast-lookup set, dropping none
// and symmetric algorithms unconditionally (RFC 9449 §4.3(5)).
func algSet(algs []jwa.SignatureAlgorithm) map[jwa.SignatureAlgorithm]struct{} {
	set := make(map[jwa.SignatureAlgorithm]struct{}, len(algs))
	for _, a := range algs {
		switch a {
		case jwa.NoSignature, jwa.HS256, jwa.HS384, jwa.HS512:
			// never permitted for DPoP
		default:
			set[a] = struct{}{}
		}
	}
	return set
}

func (v *Verifier) algAllowed(a jwa.SignatureAlgorithm) bool {
	_, ok := v.algAllow[a]
	return ok
}

// Input is the request-derived material for one enforcement decision.
type Input struct {
	// Proofs is every DPoP request-header value (r.Header.Values("DPoP")).
	Proofs []string
	// Method is the HTTP request method (htm).
	Method string
	// URL is the full request URL; query and fragment are stripped internally.
	URL string
	// AccessToken is the presented bearer used to compute ath. Treat as a
	// secret — never log it.
	AccessToken string
	// BoundJKT is the token's cnf.jkt (auth.Claims.Confirmation); "" if unbound.
	BoundJKT string
}

// Enforce applies the configured Mode and returns nil or a typed
// *auth.ErrInvalidDPoPProof. It is the single policy entry point so both
// transports apply identical fail-closed rules. The context is currently
// unused but reserved for future context-aware replay backends; callers still
// pass r.Context() to preserve the call contract.
func (v *Verifier) Enforce(_ context.Context, in Input) error {
	if in.BoundJKT != "" {
		switch len(in.Proofs) {
		case 1:
			return v.checkProof(in.Proofs[0], in, v.now())
		case 0:
			return auth.ErrInvalidDPoPProof.With(errors.New("bound token presented without a dpop proof"))
		default:
			return auth.ErrInvalidDPoPProof.With(errors.New("more than one dpop proof header"))
		}
	}
	if v.mode == Require {
		return auth.ErrInvalidDPoPProof.With(errors.New("dpop binding required but token is unbound"))
	}
	return nil // Opportunistic + unbound: plain bearer passthrough
}
