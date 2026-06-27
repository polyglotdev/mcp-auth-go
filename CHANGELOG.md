# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial extraction of the reusable Okta-JWT authentication core from the
`mcp-atlassian-go` gateway into a standalone, transport-agnostic module. The
first tagged release will be `v0.1.0`.

### Added

- **Cross App Access — ID-JAG client (`exchange` package)** — the client side of
  the Identity Assertion JWT Authorization Grant
  (`draft-ietf-oauth-identity-assertion-authz-grant-04`; the basis of MCP
  Enterprise-Managed Authorization).
  - `DownstreamTokenProvider` / `DownstreamConfig` / `NewDownstreamProvider` /
    `ProvideRequest` — runs the two-step flow: step 1 mints an ID-JAG via RFC 8693
    token exchange at the enterprise IdP; step 2 redeems it via an RFC 7523
    `jwt-bearer` grant at the Resource Authorization Server, returning a
    downstream access token. Built from two `Endpoint` configs (distinct trust
    domains — their `ClientAuth` must use distinct credentials). Final-token cache
    keyed on the explicit `Subject` (never the token bytes); one audit event per
    call (granted events carry `reason_code=cross_app_access`).
  - `(*Exchanger).RedeemAssertion` — RFC 7523 `jwt-bearer` grant primitive.
  - `Request.SubjectTokenType` / `Request.RequestedTokenType` — generalize
    `Exchange` to mint an ID-JAG. **Backward-compatible**: callers setting neither
    field emit a byte-identical request (existing `Exchange` behavior unchanged).
  - `TokenTypeIDJAG` (the non-ratified draft URN, isolated behind this constant) /
    `TokenTypeIDToken` / `TokenTypeSAML2` / `TokenTypeRefreshToken` /
    `GrantTypeJWTBearer` (RFC 7523).
  - Role boundary: the MCP server never receives the ID-JAG (the Resource AS
    validates it); it validates the resulting access token with the existing
    validators. The subject assertion, the ID-JAG, and the issued token are
    secrets — never logged, in an error cause, or a cache key. **Zero new
    dependency; no transport change.**
- **Opaque-token introspection (`introspection` package, RFC 7662)** — validate
  non-JWT (opaque) bearer tokens by calling the issuer's introspection endpoint.
  - `introspection.Validator` / `Config` / `NewValidator` — POSTs the token
    (with client authentication) to the RFC 7662 endpoint, then confirms `active`
    plus a byte-exact `iss`/`aud` match (fail closed when either is absent — the
    confused-deputy defense) and a defense-in-depth `exp` check, and builds the
    same `*auth.Claims` the JWT path does. Satisfies the `TokenValidator`
    interface, so it drops into `transport/http` and `transport/mcpauth`
    unchanged — **no transport change**.
  - `ClientAuthenticator` + `BasicAuth` (client_secret_basic) + `FormPost`
    (client_secret_post). `IntrospectionURL` must be https (loopback http allowed
    for a sidecar/tests); the response body is size-capped (DoS guard) and the
    opaque token is never logged or used as an un-hashed cache key.
  - `Cache` interface + `NewMemoryCache` — **opt-in, off by default** (every
    request introspects, so revocation is immediate). When enabled, entries are
    bounded by the response `exp` (RFC 7662 §4) and deep-copied; a response
    without `exp` is never cached. `ErrIntrospectionUnavailable` (503) is returned
    when the endpoint cannot be reached or returns a non-200/undecodable response,
    distinct from `ErrInvalidToken`. Standard library only; zero new dependencies.

- **Multi-issuer validation (`auth.MultiValidator`)** — accept tokens from more
  than one issuer (IdP migration, multi-tenant gateways, user-AS + service-AS).
  - `MultiValidatorConfig` / `NewMultiValidator` — composes one `Validator` per
    issuer (each a full `ValidatorConfig`), keyed by `iss`. Construction fails
    fast on an empty set, a duplicate issuer, or any sub-config / JWKS error.
  - `(*MultiValidator).Validate` — peeks the **unverified** `iss` (via
    `jwt.ParseInsecure`) only to route, then the matched `Validator` performs the
    real signature + per-issuer audience + verifier checks. Exact `iss` match (no
    canonicalization); an unknown, missing, or malformed `iss` fails closed with
    `ErrInvalidToken` and no JWKS fetch.
  - `TokenValidator` interface (`Validate(ctx, bearer) (*Claims, error)`),
    implemented by both `*Validator` and `*MultiValidator`. `transport/http`'s
    `MiddlewareConfig.Validator` and `transport/mcpauth`'s `RequireBearerToken` /
    `NewTokenVerifier` now accept this interface — a backward-compatible widening
    (existing `*Validator` callers compile unchanged). Zero new dependencies.

- **DPoP package (`dpop`)** — RFC 9449 resource-server enforcement
  - `Verifier` / `Config` / `NewVerifier` — validates a DPoP proof JWT against
    a bound token's `cnf.jkt` thumbprint (signature, `typ: dpop+jwt`, `htm`,
    `htu`, `iat` freshness, `ath` token binding, JWK thumbprint check).
  - `Enforce(ctx, Input)` — single entry point; decides Opportunistic vs Require
    mode from `Input.BoundJKT`; enforces the §7.2 downgrade guard (bound token
    without a proof is rejected).
  - `ReplayCache` interface + `MemoryReplayCache` (in-process `jti+htu` map) +
    `NewNopReplayCache()` (replay protection disabled; useful in tests).
  - **Distributed replay cache (`dpop/redisreplay`)** — a separate nested module
    implementing `ReplayCache` against Redis (atomic `SET NX`) for cross-instance
    proof single-use behind a load balancer. Mandatory `FailMode` (`FailOpen`
    degrades to freshness-window-only + alerting; `FailClosed` rejects all bound
    traffic on a Redis outage), error observation via an optional `slog.Logger`
    (never logs key material), and a per-call `OpTimeout`. `go-redis` is isolated
    in the module (core `go.mod`/`go.sum` unchanged); miniredis unit tests plus a
    build-tagged Testcontainers integration test (live-proven against real Redis).
  - No new third-party dependencies — imports only `auth` and the `jwx/v2`
    already present in the core module.
  - Secret hygiene: `err.Error()` exposes only constant rejection strings; the
    access token, computed `ath`, and `jkt` thumbprint never appear in error
    output. `TestNoTokenInErrorSurface` in `dpop/example_test.go` asserts this.
  - `TestOktaLiveDPoP` in `dpop/okta_live_test.go` — skip-guarded live test
    against a real Okta authorization server; run manually with credentials.
  - **RS-issued nonce (RFC 9449 §9)** — `Config.Nonce NonceSource` requires a
    fresh, server-issued nonce on every enforced proof. `SignedNonce` /
    `NewSignedNonce` is the stateless default (`base64url(ts ‖ rand ‖ HMAC-SHA256)`,
    no shared store — validates across replicas with one ≥32-byte secret).
    `Verifier.IssueNonce` / `NonceConfigured` support the transport wiring. The
    nonce check sits after the binding proof and before replay, returning the new
    `ErrUseDPoPNonce`. Complements — never replaces — the `jti` ReplayCache (the
    nonce is time-window valid, not single-use, §11.1). Stdlib-only additions
    (`crypto/hmac`, `crypto/rand`, `encoding/binary`); no new third-party deps.
- **Audit seam (`audit`) + OpenTelemetry adapter (`audit/otel`)** — the
  "Logging Service" trust signal.
  - `audit.Event` / `Action` / `Outcome` — a typed security-decision record with
    a three-tier PHI/PII partition enforced in code by `Event.MetricLabels()`
    (bounded, non-client-controlled labels) and `Event.TraceAttributes()`
    (PHI-safe attributes, never `Email`).
  - `audit.Sink` (`Record(ctx, Event)`, no error — best-effort) with
    `NewSlogSink` (default compliance sink; logs the full event incl. `Email`,
    requires a non-nil logger), `NewNopSink` (opt-out), and `NewMultiSink`
    (fan-out, compliance-sink-first).
  - Emission at the two access-decision points: `transport/mcpauth.ToolGate`
    gains `Audit`/`Now` and records each `tools/call` (granted/denied, with a
    leak-safe `reason_code` derived via `errors.As`); `exchange.Config.Audit`
    records each RFC 8693 exchange (granted/denied/error) on the cache-hit,
    success, and failure paths — never carrying token bytes.
  - **`audit/otel`** is a separate nested module (OpenTelemetry **API** only; the
    SDK is a test-only dependency) so the core's graph stays free of OTel. It
    emits the `mcp.tool.calls` / `mcp.broker.exchanges` Int64 counters (bounded
    labels) and a span event on the caller's active span; the `MeterProvider`
    is injected (defaults to the OTel global).
  - The core `audit` package is stdlib-only — **no new dependency** enters the
    core module.
- **Core (`auth`)**
  - `Claims.Confirmation` — populated from the `cnf.jkt` field of a validated
    token, carrying the JWK SHA-256 thumbprint (RFC 9449 §6.1). Empty for
    tokens that are not DPoP-bound.
  - `ErrInvalidDPoPProof` — 401 sentinel (`code: invalid_dpop_proof`) for DPoP
    failures. Match with `errors.Is`. The transport middleware challenges with
    `WWW-Authenticate: DPoP ...` when this error is returned.
  - `ErrUseDPoPNonce` — 401 sentinel (`code: use_dpop_nonce`) for the RS nonce
    demand (RFC 9449 §9). Distinct from `ErrInvalidDPoPProof`: the client retries
    with the issued `DPoP-Nonce` rather than giving up. Match with `errors.Is`.
- **Transport (`transport/http`)**
  - `MiddlewareConfig.DPoP *dpop.Verifier` — attach a verifier to enforce DPoP
    after a successful `Validate`. nil = no enforcement (backward compatible).
  - `MiddlewareConfig.BaseURL string` — override the scheme+authority used for
    `htu` reconstruction behind a TLS-terminating proxy.
  - `WWW-Authenticate` now emits `DPoP` scheme with `error="invalid_dpop_proof"`
    on DPoP failures (RFC 9449 §7.1); all other failures keep the `Bearer` scheme.
  - RS nonce (when `Config.Nonce` is set): a proof without a valid nonce yields a
    `401` + `WWW-Authenticate: DPoP error="use_dpop_nonce"` + a `DPoP-Nonce`
    header, and a successful response rotates a fresh `DPoP-Nonce` (+
    `Cache-Control: no-store`, §8.2). No new `MiddlewareConfig` field — the
    verifier carries the nonce config.
- **Transport (`transport/mcpauth`)**
  - `Options.DPoP *dpop.Verifier` and `Options.BaseURL string` — mirror the
    `transport/http` fields; enforcement runs inside the SDK's `TokenVerifier`
    closure (no separate middleware step needed).
  - `NewTokenVerifier` refactored into `newVerifierFunc` to share the DPoP path
    with `RequireBearerToken` without code duplication.
  - `RequireBearerToken` now wraps the SDK response (when `Options.DPoP` is set)
    so a DPoP failure is answered with a `DPoP`-schemed `WWW-Authenticate`
    challenge (RFC 9449 §7.1) — replacing the SDK's hard-coded `Bearer` — and a
    `use_dpop_nonce` failure carries a `DPoP-Nonce` header (§9); a successful
    response rotates a fresh `DPoP-Nonce` (§8.2, `Cache-Control: no-store` unless
    the handler set its own). RS nonce now works on this transport too (slice #3);
    the prior construction-time panic for a nonce-configured `dpop.Verifier` is
    removed. A bare `NewTokenVerifier` cannot shape the response and keeps the
    SDK's `Bearer` challenge — use `RequireBearerToken` for the DPoP challenge.
    The response wrapper implements `Unwrap`, so the SDK's streaming flush is
    unaffected.
- **Exchange package (`exchange`)** — RFC 8693 token-exchange client
  - `Exchanger` / `Config` / `NewExchanger` — RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange` POST with one-shot `use_dpop_nonce` retry and a per-caller TTL cache.
  - `Exchange(ctx, Request) (*Token, error)` — pure primitive; reads identity only from `Request`, never by parsing `SubjectToken`.
  - `TokenForCaller(ctx, audience, scope...)` — context-aware convenience: reads the raw inbound token and caller `sub` from ctx, fails closed with `auth.ErrMissingToken` when absent.
  - `ClientAuthenticator` interface + `BasicAuth` (`client_secret_basic`) + `DPoP` (RFC 9449 proof with a long-lived ES256 key; wraps any base authenticator).
  - `Cache` interface + `MemoryCache` — per-caller TTL cache keyed on `subject|audience|sorted-scope` (never token bytes); `Get` returns a defensive copy. Injected `Now` clock for deterministic tests.
  - `ErrExchangeRejected` / `ErrExchangeUnavailable` sentinels (`*auth.Error`, HTTP 502); match with `errors.Is`.
  - Secret hygiene: `Rejected` discards `error_description` to prevent AS-echoed token leaks; subject tokens never enter `err.Error()`, the JSON error body, or log output.
  - No new third-party dependencies — uses `jwx/v2` already present in the core module.
- **Core (`auth`)**
  - `WithRawToken(ctx, raw)` / `RawTokenFrom(ctx)` — carry the caller's raw bearer token alongside `WithClaims`/`ClaimsFrom` so `exchange.TokenForCaller` can reach it without parsing the token again.
- **MCP SDK adapter (`transport/mcpauth`)**
  - `RawTokenFromContext(ctx)` — reads the raw bearer token from the core key (`auth.WithRawToken`) or, as a fallback, from `NewTokenVerifier`'s stash in `TokenInfo.Extra`.
  - `ContextBridge()` — MCP receiving middleware that copies validated claims and raw bearer token from the SDK's `TokenInfo.Extra` into the core context keys (`auth.WithClaims` / `auth.WithRawToken`). Install with `server.AddReceivingMiddleware(mcpauth.ContextBridge())` so tool handlers can use `exchange.TokenForCaller` without importing the MCP SDK.

- **Core (`auth`)**
  - `Validator` / `ValidatorConfig` / `NewValidator` — JWKS-backed validation
    of Okta JWTs (signature, issuer, audience, expiry, clock skew) with a
    background-refreshing key cache and a synchronous initial fetch.
  - Pluggable authorization: the `ClaimVerifier` type and the built-in
    `VerifyRequiredStringClaims` helper. No product policy is baked into the
    validation path.
  - Typed `Claims` with context helpers `WithClaims`, `ClaimsFrom`, and
    `MustClaims`.
  - Machine-readable `*Error` model (`Is`-by-`Code`, `With` for wrapping) with
    sentinels mapping to HTTP status: `ErrMissingToken`, `ErrInvalidToken`,
    `ErrExpiredToken` (401), `ErrForbidden` (403), `ErrSessionLimitExceeded`,
    `ErrRateLimitExceeded` (429), and `ErrInvalidSession`.
  - In-memory `SessionStore` (`NewMemorySessionStore`) — per-user concurrency
    cap with a sliding timeout.
  - `RequireScopes` verifier and the `ErrInsufficientScope` (403) sentinel for
    OAuth scope enforcement.
  - Composable post-validation authorization over typed `Claims`: the
    `Authorizer` type with `AllOf`/`AnyOf` combinators, `HasScopes`/
    `HasAnyScope`/`HasClaim` predicates, and the `AllowAll`/`DenyAll` policies.
- **Transport (`transport/http`)**
  - Validating bearer-token middleware (`MiddlewareConfig`) with RFC 6750
    `WWW-Authenticate` challenges and an optional `RateLimiter` seam.
  - RFC 9728 Protected Resource Metadata handler (`MetadataHandler`) and the
    path-aware `MetadataPathFor` helper (RFC 9728 §3).
- **Transport (`transport/mcpauth`)**
  - `NewTokenVerifier` adapts a `Validator` into the official MCP Go SDK's
    `auth.TokenVerifier` (`github.com/modelcontextprotocol/go-sdk` v1.6.1),
    mapping validated `Claims` onto the SDK's `TokenInfo`
    (`Subject`→`UserID`, `ExpiresAt`→`Expiration`, scopes, and `Raw`→`Extra`).
  - `RequireBearerToken` / `Options` — one-call wiring over the SDK's
    `auth.RequireBearerToken` so callers need not import the SDK's auth package;
    required scopes route to the SDK's RFC 6750 `insufficient_scope` 403
    challenge.
  - Validation failures map to the SDK's `ErrInvalidToken` (401) carrying only
    the public message, never the wrapped cause.
  - `ToolGate` — per-tool authorization as MCP receiving middleware: authorizes
    each `tools/call` against a per-tool `auth.Authorizer` (rejecting a denied
    call with a JSON-RPC error before the tool runs) and filters `tools/list` so
    unauthorized tools are not discoverable. Fails closed for an unauthenticated
    caller. Unlisted tools allow by default; `Default: auth.DenyAll` fails closed.
  - `ClaimsFromContext` — read the authenticated caller's `auth.Claims` from a
    tool handler or gate (honors both `auth.WithClaims` and the bearer path).
  - Shipped as a separate nested module so the MCP Go SDK stays out of the core
    module's dependency graph.
- Runnable `ExampleXxx` documentation, `golangci-lint` configuration, and a
  `Makefile` gate (`make check`).

### MCP spec alignment (2025-11-25)

- `MiddlewareConfig.ResourceMetadataURL` echoes the RFC 9728 §5.1
  `resource_metadata` pointer in the `WWW-Authenticate` challenge so clients can
  discover the authorization server from a 401/403.
- `WWW-Authenticate` now uses only registered RFC 6750 error codes
  (`invalid_token`, `insufficient_scope`); missing-token and generic forbidden
  rejections omit the error parameter, and expired tokens map to `invalid_token`
  with an `error_description`.
- `MiddlewareConfig.Scopes` advertises required scopes in an
  `insufficient_scope` challenge for step-up authorization.
- Adversarial tests pin the algorithm-confusion defenses (`alg:none` and
  RS256→HS256 are rejected); `FuzzValidate` fuzzes the token parser.

### Changed (versus the `internal/auth` source)

- Replaced the hard-coded `RequiredStringClaims` field and Bedrock constants
  with injected `Verifiers`; the generic `ErrForbidden` replaces the
  Bedrock-specific `ErrBedrockRequired`.
- Removed the `Claims.Backend` field; the `claude_backend` claim now flows into
  `Claims.Raw` like any other private string claim.
