package introspection

import (
	"net/http"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// ErrIntrospectionUnavailable is returned when a network failure, timeout,
// non-200 status, or undecodable body prevented an authoritative active/inactive
// determination. The request is denied (fail-secure). It is distinct from
// auth.ErrInvalidToken: the token was not judged invalid -- the resource server
// could not reach a verdict.
var ErrIntrospectionUnavailable = &auth.Error{
	Code:       "introspection_unavailable",
	Message:    "The token could not be validated: the introspection endpoint was unavailable.",
	HTTPStatus: http.StatusServiceUnavailable,
}

// Unavailable wraps a transport- or protocol-level failure as
// ErrIntrospectionUnavailable. The cause is for logs only; by construction it
// never contains the token or any response-body value (see the package no-leak
// discipline) -- only transport/ctx errors, status codes, or json decode errors.
func Unavailable(cause error) *auth.Error { return ErrIntrospectionUnavailable.With(cause) }
