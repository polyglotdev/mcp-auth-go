// Package mcpauth adapts an mcp-auth-go Validator to the official MCP Go SDK's
// bearer-token middleware, so an SDK-based MCP server validates issuer JWTs —
// signature, iss/aud/exp, and the RFC 8707 audience check — in one line.
//
// # Why this exists
//
// The SDK ships bearer middleware and RFC 9728 metadata, but its TokenVerifier
// hook (github.com/modelcontextprotocol/go-sdk/auth.TokenVerifier) is left to
// the caller and the SDK itself performs no audience check — the requirement
// MCP servers most often miss. This package fills that hole: [NewTokenVerifier]
// turns a Validator, which does the JWKS, signature, iss/aud/exp, and skew
// validation, into a drop-in TokenVerifier.
//
// # Recommended usage
//
// [RequireBearerToken] wires the validator and the SDK middleware together so
// callers need not import the SDK's auth package:
//
//	v, _ := auth.NewValidator(ctx, auth.ValidatorConfig{ /* ... */ })
//	secured := mcpauth.RequireBearerToken(v, &mcpauth.Options{
//		ResourceMetadataURL: prmURL,
//		Scopes:              []string{"mcp:read"},
//	})(mcpHandler)
//
// Use [NewTokenVerifier] directly when you'd rather call the SDK's
// RequireBearerToken yourself.
//
// # Status mapping
//
// The SDK's TokenVerifier contract supports exactly one verifier-level
// rejection: an error that unwraps to its ErrInvalidToken sentinel, which it
// answers with 401 (anything else becomes a 500). This package therefore maps
// every validation failure — authentication failures (bad signature, wrong
// audience, expired) and authorization failures (a ClaimVerifier returning
// ErrForbidden or ErrInsufficientScope) — to 401, exposing only the failure's
// public message and never the wrapped cause (the SDK writes the error string
// as the response body).
//
// A 403 is reachable only through the SDK's own scope check: set [Options].Scopes
// and the SDK answers an insufficient scope with a 403 and an RFC 6750 scope
// challenge. Prefer that over auth.RequireScopes on the Validator, which this
// adapter can only surface as 401.
//
// # DPoP proof-of-possession
//
// Set [Options].DPoP to enforce RFC 9449 after a successful Validate.
// [RequireBearerToken] then wraps the SDK response so a DPoP failure is answered
// with a DPoP-schemed WWW-Authenticate challenge (RFC 9449 §7.1) instead of the
// SDK's hard-coded Bearer scheme, and — when the verifier carries a nonce
// (dpop.Config.Nonce) — a DPoP-Nonce header (§9) the client retries with; a
// successful response rotates a fresh DPoP-Nonce (§8.2). A bare
// [NewTokenVerifier] cannot shape the response, so it yields the SDK's Bearer
// challenge; use [RequireBearerToken] for the DPoP challenge and nonce.
//
// # Per-tool authorization
//
// Bearer scopes gate the whole endpoint; [ToolGate] gates individual MCP tools.
// Installed with server.AddReceivingMiddleware, it authorizes each tools/call
// against a per-tool [auth.Authorizer] using the caller's claims -- rejecting an
// unauthorized call with a JSON-RPC error before the tool runs -- and filters
// tools/list so a caller only discovers the tools it may use. It fails closed:
// with no authenticated caller, a call is denied and the tool list is empty.
// Read the caller in your own tool handlers with [ClaimsFromContext].
//
// # RFC 8693 token exchange (broker)
//
// To exchange the caller's inbound token for a downstream service token inside
// a tool handler, use the exchange package from the core module:
//
//	ex, _ := exchange.NewExchanger(exchange.Config{ /* ... */ })
//	tok, err := ex.TokenForCaller(ctx, "api://downstream", "svc:read")
//
// TokenForCaller reads auth.RawTokenFrom(ctx) and auth.ClaimsFrom(ctx). On the
// bearer HTTP path these are set by the HTTP middleware (transport/http). On
// the SDK path they are NOT set automatically -- install [ContextBridge] to
// copy them from the SDK's TokenInfo before your method handlers run:
//
//	server.AddReceivingMiddleware(mcpauth.ContextBridge())
//
// [ContextBridge] copies the validated claims and raw bearer token from
// TokenInfo.Extra (placed there by [NewTokenVerifier]) into the core context
// keys (auth.WithClaims / auth.WithRawToken). It is a no-op for unauthenticated
// requests. [RawTokenFromContext] reads the raw bearer token directly from
// either the core key or the SDK's TokenInfo.Extra fallback.
//
// # Module boundary
//
// This adapter is a separate nested module so the SDK dependency stays out of
// the core module's graph: code that imports only the core
// github.com/polyglotdev/mcp-auth-go package never pulls in the MCP Go SDK.
package mcpauth
