// Package introspection is an RFC 7662 OAuth 2.0 Token Introspection client: it
// validates an opaque (non-JWT) bearer token by POSTing it -- with client
// authentication -- to an authorization server's introspection endpoint, reading
// the active flag plus the returned claims, and building an *auth.Claims.
//
// The introspection Validator satisfies auth.TokenValidator, so it drops into
// the same transports a JWT auth.Validator does, with no transport change. It
// depends only on the core auth package (for the shared Claims, the typed Error
// sentinels, and the TokenValidator seam) and the standard library -- never on
// jwx (opaque tokens are never parsed), a transport, OpenTelemetry, or go-redis.
//
// Unlike local JWT validation, introspection is a network call to a credentialed
// endpoint that returns authorization-server-controlled JSON. The Validator
// therefore authenticates itself to the endpoint (RFC 7662 section 4), confirms
// the returned issuer and audience itself (an introspection endpoint can report
// a token minted for a different resource as active), treats the opaque token as
// a secret (never logged, never an un-hashed cache key), and fails closed
// whenever it cannot obtain an authoritative active:true.
package introspection
