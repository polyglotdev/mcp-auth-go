package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// MultiValidatorConfig configures a MultiValidator. Each entry in Issuers is a
// full ValidatorConfig (its own JWKSURL, Issuer, Audience, Verifiers, and
// refresh/skew knobs), so different trusted issuers can enforce different
// audiences and authorization policies. At least one entry is required, and
// each entry's Issuer must be unique across the set.
type MultiValidatorConfig struct {
	// Issuers is the set of trusted issuers. A token is routed to the entry
	// whose Issuer exactly equals the token's iss claim. For multi-tenant
	// isolation, give each issuer a distinct Audience (the same Audience across
	// issuers is allowed but collapses audience-based isolation).
	Issuers []ValidatorConfig
}

// MultiValidator validates a bearer token against a configured set of trusted
// issuers, selecting the per-issuer Validator by the token's iss claim. A single
// resource server can thus accept tokens from more than one authorization server
// (IdP migration, multi-tenant gateways, or a user-AS + service-AS split).
// Construct it with NewMultiValidator.
//
// Routing reads the UNVERIFIED iss claim only to select which issuer's
// configuration applies; the matched Validator then performs the real signature
// verification against that issuer's JWKS plus its iss/aud/verifier checks, so
// the cryptographic check -- not the unverified peek -- is what binds the token.
//
// iss is matched by EXACT string equality (no canonicalization): configure each
// Issuer to the byte-identical value the issuer emits, exactly as for a single
// Validator. A token whose iss is unknown, missing, or unparseable fails closed
// as ErrInvalidToken and triggers no JWKS fetch.
//
// Configured issuers MUST NOT share signing key material: routing is by iss and
// each Validator verifies independently, so a key shared between two issuers
// would let a holder of that key mint a token accepted under either.
type MultiValidator struct {
	byIssuer map[string]*Validator
}

var _ TokenValidator = (*MultiValidator)(nil)

// NewMultiValidator validates cfg and builds one Validator per issuer, reusing
// NewValidator (which checks each entry's required fields, performs a
// synchronous initial JWKS fetch, and ties background refresh to ctx). Pass the
// service lifecycle ctx; a misconfigured or unreachable issuer fails fast here
// rather than on the first request.
//
// It returns an error when Issuers is empty, when two entries share an Issuer
// (ambiguous routing), or when any entry's NewValidator fails. It does not
// retain cfg, so the caller may reuse or mutate cfg.Issuers afterward.
func NewMultiValidator(ctx context.Context, cfg MultiValidatorConfig) (*MultiValidator, error) {
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("auth: multivalidator: at least one issuer is required")
	}
	byIssuer := make(map[string]*Validator, len(cfg.Issuers))
	for i, ic := range cfg.Issuers {
		if _, dup := byIssuer[ic.Issuer]; dup {
			return nil, fmt.Errorf("auth: multivalidator: duplicate issuer %q", ic.Issuer)
		}
		v, err := NewValidator(ctx, ic)
		if err != nil {
			return nil, fmt.Errorf("auth: multivalidator: issuer %d (%q): %w", i, ic.Issuer, err)
		}
		byIssuer[ic.Issuer] = v
	}
	return &MultiValidator{byIssuer: byIssuer}, nil
}

// Validate peeks the token's unverified iss to route to the matching issuer's
// Validator, which performs the real verification. A missing, empty, malformed,
// or unconfigured iss fails closed as ErrInvalidToken with a constant cause
// (never the token or the iss value) and triggers no JWKS fetch. On a match, the
// matched Validator's typed result -- Claims or a typed Error (ErrInvalidToken,
// ErrExpiredToken, ErrForbidden, ErrInsufficientScope) -- is returned unchanged.
func (m *MultiValidator) Validate(ctx context.Context, bearer string) (*Claims, error) {
	if bearer == "" {
		return nil, ErrMissingToken
	}
	// ParseInsecure skips signature verification and all standard-claim
	// validation; it is used only to read the iss routing key. The matched
	// Validator below performs the real signature and claim checks.
	tok, err := jwt.ParseInsecure([]byte(bearer))
	if err != nil {
		return nil, ErrInvalidToken.With(errors.New("malformed token"))
	}
	iss := tok.Issuer()
	if iss == "" {
		return nil, ErrInvalidToken.With(errors.New("issuer claim missing"))
	}
	v, ok := m.byIssuer[iss]
	if !ok {
		// Fail closed. The cause is a constant -- never the token-supplied iss --
		// so it cannot leak into logs or (via Error()) any surfaced message.
		return nil, ErrInvalidToken.With(errors.New("issuer not configured"))
	}
	return v.Validate(ctx, bearer)
}
