package mcpauth

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth "github.com/polyglotdev/mcp-auth-go"
)

// ContextBridge returns MCP receiving middleware that copies the authenticated
// caller's claims and raw bearer token from the SDK's TokenInfo into the core
// context keys (auth.WithClaims / auth.WithRawToken). Install it with
//
//	server.AddReceivingMiddleware(mcpauth.ContextBridge())
//
// so tool handlers can use transport-agnostic core helpers -- auth.ClaimsFrom,
// auth.RawTokenFrom, and exchange.Exchanger.TokenForCaller -- without importing
// the MCP SDK. It is a no-op for unauthenticated requests.
func ContextBridge() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if c, ok := ClaimsFromContext(ctx); ok {
				ctx = auth.WithClaims(ctx, c)
			}
			if raw, ok := RawTokenFromContext(ctx); ok {
				ctx = auth.WithRawToken(ctx, raw)
			}
			return next(ctx, method, req)
		}
	}
}
