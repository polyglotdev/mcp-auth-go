// Package dpop enforces RFC 9449 (DPoP) proof-of-possession on the resource
// server: when a caller presents a DPoP-bound access token (one carrying a
// cnf.jkt confirmation), it verifies a DPoP proof JWT against that binding.
//
// Enforce is the single policy entry point; Mode selects opportunistic
// (enforce only bound tokens) or require (mandate binding for every token). It
// depends only on the core auth package and jwx -- never on a transport.
//
// htu behind a proxy: the proof's htu is the PUBLIC request URL the client
// signed. Behind a TLS-terminating proxy a server reconstructs htu from the
// internal hop and would reject every proof; the transports expose a BaseURL
// override for the public scheme+authority. See transport/http MiddlewareConfig.
//
// RS-issued nonce (RFC 9449 §9): set Config.Nonce (e.g. a SignedNonce, the
// stateless HMAC default) to require every enforced proof to carry a fresh,
// server-issued nonce. A bound proof lacking a valid nonce yields
// ErrUseDPoPNonce; transport/http answers 401 with a DPoP-Nonce header so the
// client retries, and rotates a fresh nonce onto successful responses (§8.2).
// The nonce complements -- never replaces -- the jti ReplayCache: it is
// time-window valid, not single-use (§11.1). Enabling it is a posture change: a
// client must support the use_dpop_nonce retry and pays one cold-start
// round-trip. Supported on both transports: transport/http natively, and
// transport/mcpauth via a response-wrapping middleware that rewrites the SDK's
// challenge and emits/rotates the DPoP-Nonce (slice #3). On transport/mcpauth
// this requires its RequireBearerToken wrapper; a bare NewTokenVerifier cannot
// shape the response and falls back to the SDK's Bearer challenge.
package dpop
