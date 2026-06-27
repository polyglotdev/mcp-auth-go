package auth

import "context"

// ctxClaimsKey is the unexported context key used by WithClaims/ClaimsFrom.
// Unexported per the Go context idiom -- callers must use the helpers.
type ctxClaimsKey struct{}

// WithClaims returns a derived context carrying c. A transport adapter calls
// this after a successful Validate so downstream handlers can read the
// authenticated user without re-parsing the token.
func WithClaims(parent context.Context, c *Claims) context.Context {
	return context.WithValue(parent, ctxClaimsKey{}, c)
}

// ClaimsFrom retrieves the verified Claims placed on the context by a
// transport adapter. It returns (nil, false) for unauthenticated contexts --
// which means the auth middleware was bypassed, a programming bug.
func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxClaimsKey{}).(*Claims)
	return c, ok
}

// MustClaims returns the verified Claims from ctx, panicking if absent.
//
// The Must prefix follows the Go convention (regexp.MustCompile, template.Must)
// for helpers that panic on failure. Use it inside handlers that MUST run
// behind the auth middleware: a missing value is an invariant violation (the
// handler was wired without auth in front of it), not a runtime condition, so
// failing loudly at the bug's source is preferable to a nil dereference deeper
// in the request. Callers that want to handle absence should use ClaimsFrom.
func MustClaims(ctx context.Context) *Claims {
	c, ok := ClaimsFrom(ctx)
	if !ok {
		panic("auth: MustClaims called on unauthenticated context") // invariant: the auth middleware guarantees claims before handlers run
	}
	return c
}

// ctxRawTokenKey is the unexported context key for WithRawToken/RawTokenFrom.
type ctxRawTokenKey struct{}

// WithRawToken returns a derived context carrying the caller's raw bearer token.
// A transport adapter calls this alongside WithClaims so a broker (RFC 8693
// token exchange) can use the original token as the subject_token. The value is
// a secret -- never log it.
func WithRawToken(parent context.Context, raw string) context.Context {
	return context.WithValue(parent, ctxRawTokenKey{}, raw)
}

// RawTokenFrom retrieves the raw bearer token placed on the context by a
// transport adapter. It returns ("", false) when absent.
func RawTokenFrom(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(ctxRawTokenKey{}).(string)
	return s, ok
}
