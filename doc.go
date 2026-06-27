// Package auth validates Okta-issued JWTs and turns them into typed,
// transport-agnostic claims for secure internal MCP services.
//
// A [Validator] checks a bearer token against a JWKS endpoint — signature,
// issuer, audience, expiry, and clock skew — then runs any number of injected
// [ClaimVerifier] policies. On success it returns typed [Claims] that
// downstream code reads without importing jwx. HTTP middleware and RFC 9728
// metadata live in the transport/http subpackage, which depends on this
// package and never the other way around.
//
// # Authentication versus authorization
//
// The package keeps the two concerns apart, and so should callers.
// Authentication — "is this a genuine, unexpired token from the issuer we
// trust?" — is fixed: signature, iss, aud, exp/nbf. Authorization — "is this
// caller allowed here?" — is yours to define, as [ClaimVerifier] functions in
// [ValidatorConfig.Verifiers]. The core hard-codes no policy;
// [VerifyRequiredStringClaims] covers the common case (a claim must equal a
// value) and you can write your own. Authentication failures map to 401;
// verifier failures map to 403.
//
// For authorization that runs after validation -- in particular per-tool gating
// at the MCP layer -- the package also provides composable [Authorizer] policies
// over typed [Claims]: combine [HasScopes], [HasAnyScope], and [HasClaim] with
// [AllOf] and [AnyOf]. The transport/mcpauth ToolGate applies one Authorizer per
// MCP tool.
//
// # Errors
//
// Validation failures are typed [Error] values that stay distinguishable with
// errors.Is and carry the HTTP status a transport should send:
//
//	ErrMissingToken       missing or non-Bearer Authorization header   401
//	ErrInvalidToken       bad signature, wrong iss/aud, malformed       401
//	ErrExpiredToken       exp is in the past                            401
//	ErrForbidden          a verifier rejected an authenticated token    403
//	ErrInsufficientScope  a required OAuth scope is missing             403
//
// A verifier returns [ErrForbidden] (wrapped with the offending detail); the
// wrapped cause is logged but never serialized to a client. Failures are
// fail-closed: any ambiguity returns a 4xx, never a 5xx a client might
// auto-retry.
//
// # Sessions
//
// [NewMemorySessionStore] offers an optional, transport-neutral per-user
// concurrency cap with a sliding timeout — useful for bounding concurrent MCP
// sessions per user. It is not authentication: every request must still
// validate its bearer token (the MCP spec requires this), and the store only
// bounds concurrency.
//
// # Thread safety
//
// A [Validator] is safe for concurrent use by many goroutines, as is the store
// returned by [NewMemorySessionStore].
package auth
