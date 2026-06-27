package exchange

import (
	"net/http"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// ErrExchangeRejected is returned when the authorization server returned an
// OAuth error for the exchange (e.g. invalid_grant, invalid_target,
// invalid_scope, invalid_dpop_proof). Match with errors.Is.
var ErrExchangeRejected = &auth.Error{
	Code:       "exchange_rejected",
	Message:    "The authorization server rejected the token exchange.",
	HTTPStatus: http.StatusBadGateway,
}

// ErrExchangeUnavailable is returned when a network failure, timeout, or 5xx
// response prevents the exchange from completing.
var ErrExchangeUnavailable = &auth.Error{
	Code:       "exchange_unavailable",
	Message:    "The authorization server could not be reached for token exchange.",
	HTTPStatus: http.StatusBadGateway,
}

// Rejected builds an ErrExchangeRejected naming the AS error code in the
// public message. The AS error_description is intentionally discarded: it is
// AS-controlled text and may echo back content from the exchange request (e.g.
// the subject token) in misconfigured or malicious scenarios. Callers that want
// the raw AS description should log it before calling Rejected.
// asError is the OAuth error code returned by the AS (e.g. "invalid_grant").
func Rejected(asError, _ string) *auth.Error {
	out := *ErrExchangeRejected
	out.Message = "token exchange rejected by the authorization server: " + asError
	return &out
}

// Unavailable wraps a transport-level failure as ErrExchangeUnavailable.
func Unavailable(cause error) *auth.Error { return ErrExchangeUnavailable.With(cause) }
