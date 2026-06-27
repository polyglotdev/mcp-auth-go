package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ValidatorConfig configures a Validator. JWKSURL, Issuer, and Audience are
// required; the rest have safe defaults.
type ValidatorConfig struct {
	// JWKSURL is the issuer's JWKS endpoint
	// (e.g. https://acme.okta.com/oauth2/aus123/v1/keys).
	JWKSURL string

	// Issuer is the expected `iss` claim
	// (e.g. https://acme.okta.com/oauth2/aus123).
	Issuer string

	// Audience is the expected `aud` claim
	// (e.g. https://mcp.internal.acme.com).
	Audience string

	// MinRefreshInterval bounds how often the JWKS cache refreshes from the
	// issuer. Defaults to 15 minutes; values below 1 minute are clamped.
	MinRefreshInterval time.Duration

	// ClockSkew is the tolerance applied to exp/nbf/iat. 30 seconds is the
	// usual default; tighter values cause spurious 401s under clock drift.
	ClockSkew time.Duration

	// Verifiers are authorization-policy checks run, in order, after the
	// signature and standard claims validate. The first verifier to return a
	// non-nil error fails the request; its error is returned unchanged so a
	// transport adapter can map it to the right status. Use them to enforce
	// required claims, scopes, or other policy -- see VerifyRequiredStringClaims.
	//
	// Verifiers are optional: a nil or empty slice means signature + standard
	// claims are the only gate.
	Verifiers []ClaimVerifier
}

// Validator validates issuer-issued JWTs and runs configured authorization
// verifiers. Construct with NewValidator; the underlying JWKS cache runs
// background refresh goroutines tied to the construction context's lifetime.
type Validator struct {
	cfg   ValidatorConfig
	cache *jwk.Cache
}

// TokenValidator validates a bearer token and returns typed Claims. Both
// *Validator (a single issuer) and *MultiValidator (a configured set of trusted
// issuers) satisfy it, so a transport adapter can accept either.
//
// Implementations return typed *Error values so callers classify failures with
// errors.Is: ErrMissingToken (empty bearer), ErrInvalidToken (bad signature,
// wrong iss/aud, malformed, or unconfigured issuer), ErrExpiredToken (past exp),
// or a configured ClaimVerifier's error (by convention ErrForbidden /
// ErrInsufficientScope for an authenticated but unauthorized caller).
type TokenValidator interface {
	Validate(ctx context.Context, bearer string) (*Claims, error)
}

var _ TokenValidator = (*Validator)(nil)

// NewValidator creates a Validator with a primed JWKS cache. The provided ctx
// controls the cache's background refresh goroutines -- when ctx is cancelled,
// the cache stops refreshing. Pass the service's lifecycle ctx.
//
// The initial JWKS fetch is performed synchronously so a misconfigured URL
// fails fast at startup rather than on the first request.
//
// It returns an error if JWKSURL, Issuer, or Audience is empty, or if the
// initial JWKS fetch fails.
func NewValidator(ctx context.Context, cfg ValidatorConfig) (*Validator, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("auth: ValidatorConfig.JWKSURL is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("auth: ValidatorConfig.Issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("auth: ValidatorConfig.Audience is required")
	}
	if cfg.MinRefreshInterval < time.Minute {
		cfg.MinRefreshInterval = 15 * time.Minute
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 30 * time.Second
	}

	cache := jwk.NewCache(ctx)
	if err := cache.Register(cfg.JWKSURL, jwk.WithMinRefreshInterval(cfg.MinRefreshInterval)); err != nil {
		return nil, fmt.Errorf("auth: register jwks %q: %w", cfg.JWKSURL, err)
	}
	if _, err := cache.Refresh(ctx, cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("auth: initial jwks fetch %q: %w", cfg.JWKSURL, err)
	}

	return &Validator{cfg: cfg, cache: cache}, nil
}

// Validate parses and verifies a bearer token, returning typed Claims on
// success. Failures are typed [Error] values, so a transport adapter can map
// them to a status with errors.Is and never has to re-classify:
//
//	ErrMissingToken   bearer is empty
//	ErrExpiredToken   the token's exp is in the past
//	ErrInvalidToken   bad signature, wrong iss/aud, malformed, or JWKS unreachable
//
// plus whatever a configured [ClaimVerifier] returns first — by convention
// [ErrForbidden] for an authenticated but unauthorized caller.
func (v *Validator) Validate(ctx context.Context, bearer string) (*Claims, error) {
	if bearer == "" {
		return nil, ErrMissingToken
	}

	set, err := v.cache.Get(ctx, v.cfg.JWKSURL)
	if err != nil {
		// JWKS endpoint is down. Treat as auth failure (401), not a 5xx --
		// retrying with the same token would still fail. The cache keeps
		// trying in the background.
		return nil, ErrInvalidToken.With(fmt.Errorf("jwks unavailable: %w", err))
	}

	tok, err := jwt.Parse(
		[]byte(bearer),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithAcceptableSkew(v.cfg.ClockSkew),
	)
	if err != nil {
		// Differentiate expired-token (so the client knows to re-auth) from
		// other validation errors.
		if isExpiredError(err) {
			return nil, ErrExpiredToken.With(err)
		}
		return nil, ErrInvalidToken.With(err)
	}

	// Authorization verifiers gate at the AUTHORIZATION level -- the token is
	// valid and the caller is who they say they are, but policy may still
	// reject them. Run in order; the first failure wins.
	for _, verify := range v.cfg.Verifiers {
		if err := verify(ctx, tok); err != nil {
			return nil, err
		}
	}

	return claimsFromToken(tok), nil
}

// isExpiredError tells whether the jwx validation failure was an expiration
// problem (so we can return ErrExpiredToken with the more actionable message
// rather than the generic ErrInvalidToken). jwx exposes this via a
// package-level sentinel matched with errors.Is.
func isExpiredError(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired())
}
