package auth

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is the structured response body returned for any auth-related
// rejection.
//
// The shape is fixed so a client can render it and runbooks can be linked.
// DocURL points at a relevant runbook (when one exists) so a misconfigured
// caller is one click from a fix.
type Error struct {
	// Code is the machine-readable error identifier. Examples:
	//   invalid_token, expired_token, missing_token, forbidden,
	//   session_limit_exceeded, rate_limit_exceeded.
	Code string `json:"error"`

	// Message is the human-readable explanation safe to show in a CLI.
	// Never contains PHI -- only configuration/posture diagnostics.
	Message string `json:"message"`

	// DocURL points to the runbook covering this specific failure. May be
	// empty if no runbook exists.
	DocURL string `json:"doc_url,omitempty"`

	// HTTPStatus is the response status to send. Not serialized to the body;
	// used by transport adapters when writing the response.
	HTTPStatus int `json:"-"`

	// Cause wraps the underlying error for logging. NEVER included in the
	// response body (it might contain validator internals that aid attackers).
	Cause error `json:"-"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("auth: %s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("auth: %s: %s", e.Code, e.Message)
}

// Unwrap exposes the underlying cause for errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.Cause }

// Sentinel errors. Use errors.Is to test against these in handlers and tests.
var (
	// ErrInvalidToken: token is malformed, the signature doesn't verify, or
	// required base claims (sub, exp) are missing/wrong.
	ErrInvalidToken = &Error{
		Code:       "invalid_token",
		Message:    "The bearer token could not be validated.",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrExpiredToken: the token's exp claim is in the past.
	ErrExpiredToken = &Error{
		Code:       "expired_token",
		Message:    "The bearer token has expired. Re-authenticate with the issuer.",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrMissingToken: no Authorization header (or it's not "Bearer ...").
	ErrMissingToken = &Error{
		Code:       "missing_token",
		Message:    "Authorization: Bearer <token> is required.",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrForbidden: the token validated cleanly (the caller is who they say
	// they are) but an authorization verifier rejected the request -- a
	// required claim was missing, the wrong type, or did not match. This is
	// the 403 that gates policy such as backend or scope requirements.
	//
	// Verifiers attach the specific reason via With; the public Message is
	// intentionally generic so it never leaks which claim failed.
	ErrForbidden = &Error{
		Code:       "forbidden",
		Message:    "The token is valid but not authorized for this resource.",
		HTTPStatus: http.StatusForbidden,
	}

	// ErrInsufficientScope: the token is valid but lacks a required OAuth
	// scope. It is distinct from ErrForbidden because RFC 6750 defines
	// insufficient_scope as a registered 403 error code that a transport
	// echoes in the WWW-Authenticate challenge (with the required scopes), so
	// a client can request step-up authorization. See RequireScopes.
	ErrInsufficientScope = &Error{
		Code:       "insufficient_scope",
		Message:    "The token is missing a required scope for this resource.",
		HTTPStatus: http.StatusForbidden,
	}

	// ErrSessionLimitExceeded: the user already has the maximum number of
	// concurrent sessions open. They must close one before opening another.
	ErrSessionLimitExceeded = &Error{
		Code:       "session_limit_exceeded",
		Message:    "Too many concurrent sessions for this user. Close an existing session and retry.",
		HTTPStatus: http.StatusTooManyRequests,
	}

	// ErrRateLimitExceeded: the per-user rate limit was hit. Transport
	// adapters also add a Retry-After header.
	ErrRateLimitExceeded = &Error{
		Code:       "rate_limit_exceeded",
		Message:    "Per-user rate limit exceeded. Wait and retry; see Retry-After header for cooldown.",
		HTTPStatus: http.StatusTooManyRequests,
	}

	// ErrInvalidDPoPProof: a DPoP-bound token was presented without a valid
	// proof of possession (missing/multiple/malformed proof, bad signature,
	// htm/htu mismatch, stale iat, ath mismatch, thumbprint mismatch, or
	// replay), OR a bound token was presented as a plain bearer (RFC 9449 §7.2
	// downgrade), OR Require mode received an unbound token. Maps to RFC 9449
	// §7.1 error="invalid_dpop_proof". The specific reason is wrapped via With
	// for logs only; the public Message never varies.
	ErrInvalidDPoPProof = &Error{
		Code:       "invalid_dpop_proof",
		Message:    "The DPoP proof is missing or invalid.",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrUseDPoPNonce: DPoP nonce enforcement is enabled (RFC 9449 §9) and an
	// otherwise-valid proof carried no nonce, or a stale/forged one. Distinct
	// from ErrInvalidDPoPProof because the client remedy differs: retry with the
	// DPoP-Nonce the server just issued, not give up. Maps to RFC 9449 §9 /
	// §12.2 error="use_dpop_nonce" (DPoP scheme). The specific reason is wrapped
	// via With for logs only; the public Message never varies.
	ErrUseDPoPNonce = &Error{
		Code:       "use_dpop_nonce",
		Message:    "A DPoP nonce is required; retry with the provided DPoP-Nonce.",
		HTTPStatus: http.StatusUnauthorized,
	}
)

// With produces a copy of a sentinel error with a wrapped cause for logging.
// Use this instead of fmt.Errorf so the sentinel comparison still works:
//
//	return auth.ErrInvalidToken.With(err)
//	...
//	if errors.Is(returned, auth.ErrInvalidToken) { ... }   // still matches
func (e *Error) With(cause error) *Error {
	out := *e
	out.Cause = cause
	return &out
}

// Is implements errors.Is by comparing Code. This means a wrapped copy of a
// sentinel compares equal to the sentinel itself.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return e.Code == t.Code
}
