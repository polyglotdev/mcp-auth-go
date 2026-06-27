package exchange

import (
	"context"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// TokenForCaller exchanges the caller's inbound token (read from ctx via
// auth.RawTokenFrom) for a downstream token, keying the cache on the caller's
// sub (auth.ClaimsFrom). It fails closed: a ctx without a raw token (the auth
// middleware was bypassed) returns auth.ErrMissingToken and performs no
// exchange. On the MCP SDK transport, install mcpauth.ContextBridge() so the
// ctx keys resolve.
func (x *Exchanger) TokenForCaller(ctx context.Context, audience string, scope ...string) (*Token, error) {
	raw, ok := auth.RawTokenFrom(ctx)
	if !ok || raw == "" {
		return nil, auth.ErrMissingToken
	}
	subject := ""
	if claims, ok := auth.ClaimsFrom(ctx); ok {
		subject = claims.Subject
	}
	return x.Exchange(ctx, Request{
		SubjectToken: raw,
		Subject:      subject,
		Audience:     audience,
		Scope:        scope,
	})
}
