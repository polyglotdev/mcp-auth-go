# Architecture — `mcp-auth-go`

This module is the reusable authentication/authorization core extracted from
the HealthBridge Atlassian MCP gateway (`mcp-atlassian-go/internal/auth`). It
is transport-agnostic: any secure internal MCP server can import it to validate
Okta-issued JWTs, consume typed claims, and enforce its own authorization
policy.

## Package layout

```bash
github.com/polyglotdev/mcp-auth-go            ← core (package auth)
├── errors.go        *Error model + sentinels (incl. ErrForbidden, ErrInvalidDPoPProof)
├── claims.go        Claims type + claimsFromToken / scope parsing
│                    Claims.Confirmation ← JWK thumbprint from cnf.jkt (RFC 9449)
├── context.go       WithClaims / ClaimsFrom / MustClaims
│                    WithRawToken / RawTokenFrom  ← raw bearer token for RFC 8693 exchange
├── verifier.go      ClaimVerifier + VerifyRequiredStringClaims
├── validator.go     ValidatorConfig / NewValidator / Validate
│                    TokenValidator interface ← the seam both transports accept
├── multivalidator.go MultiValidatorConfig / NewMultiValidator — N Validators
│                    keyed by issuer; routes by unverified iss (multi-issuer)
├── session.go       SessionStore + in-memory implementation
├── session_id.go    crypto-random session id generator
│
├── dpop/            ← RFC 9449 resource-server enforcement (package dpop)
│   ├── doc.go          package overview
│   ├── verifier.go     Config / Verifier / NewVerifier / Enforce
│   ├── proof.go        checkProof — signature, typ, htm, htu, iat, ath, jkt checks
│   └── replay.go       ReplayCache interface + MemoryReplayCache / NopReplayCache
│
├── exchange/        ← RFC 8693 token-exchange client + ID-JAG client (package exchange)
│   ├── doc.go          package overview
│   ├── token.go        Token struct (result of a successful exchange)
│   ├── request.go      Request struct (Subject/RequestedTokenType drive ID-JAG minting)
│   ├── errors.go       ErrExchangeRejected / ErrExchangeUnavailable sentinels
│   ├── cache.go        Cache interface + MemoryCache (per-caller TTL cache)
│   ├── clientauth.go   ClientAuthenticator interface + BasicAuth
│   ├── dpop.go         DPoP decorator (RFC 9449 proof, long-lived ES256 key)
│   ├── exchanger.go    Config / Exchanger / NewExchanger / Exchange / RedeemAssertion (RFC 7523)
│   ├── idjag.go        Cross App Access: URN constants + DownstreamTokenProvider (two-step ID-JAG)
│   └── helper.go       TokenForCaller (context-aware convenience over Exchange)
│
├── introspection/   ← RFC 7662 opaque-token introspection (package introspection)
│   ├── doc.go          package overview
│   ├── errors.go       ErrIntrospectionUnavailable sentinel + Unavailable helper
│   ├── clientauth.go   ClientAuthenticator interface + BasicAuth + FormPost
│   ├── cache.go        Cache interface + MemoryCache (opt-in; deep-copy; exp-bounded)
│   └── introspection.go Config / Validator / NewValidator / Validate (satisfies auth.TokenValidator)
│
├── audit/           ← security-audit seam (package audit; stdlib only)
│   ├── event.go        Event + Action/Outcome/Attr + MetricLabels/TraceAttributes (3-tier partition)
│   └── sink.go         Sink interface + NewSlogSink / NewNopSink / NewMultiSink
│
├── transport/http   ← HTTP adapter (package http)
│   ├── middleware.go   bearer extraction, validation, WWW-Authenticate, rate limiting
│   │                   DPoP enforcement via MiddlewareConfig.DPoP + BaseURL
│   │                   populates auth.WithRawToken so exchange.TokenForCaller works
│   └── metadata.go     RFC 9728 Protected Resource Metadata handler
│
└── internal/jwkstest ← test-only helper (mints JWTs, serves a JWKS)
```

The `transport/mcpauth` adapter is a separate nested module
(`github.com/polyglotdev/mcp-auth-go/transport/mcpauth`) so the MCP Go SDK
dependency never enters the core module's graph.

```bash
transport/mcpauth/
├── verifier.go      NewTokenVerifier / newVerifierFunc / RawTokenFromContext / ClaimsFromContext
│                    DPoP enforcement via Options.DPoP (calls dpop.Verifier.Enforce)
├── context.go       ContextBridge() — copies TokenInfo into core ctx keys
├── middleware.go    RequireBearerToken / Options (incl. DPoP + BaseURL)
├── challenge.go     DPoP challenge wrapper — rewrites the SDK's Bearer challenge
│                    to DPoP scheme (+ DPoP-Nonce / rotation) via an Unwrap-able ResponseWriter
└── toolgate.go      ToolGate — per-tool authorization (+ audit emission) as MCP receiving middleware
```

The `audit/otel` adapter is likewise a separate nested module
(`github.com/polyglotdev/mcp-auth-go/audit/otel`) so the OpenTelemetry SDK
dependency never enters the core module's graph (the adapter compiles against
the OTel **API** only; the SDK is a test-only dependency).

```bash
audit/otel/
├── sink.go         NewSink / Config — Event → Int64 counter + active-span event
└── doc.go          package overview (OTel API only; SDK is test-only)
```

The `dpop/redisreplay` adapter is likewise a separate nested module
(`github.com/polyglotdev/mcp-auth-go/dpop/redisreplay`) so the Redis client
(`go-redis`) never enters the core module's graph — a Redis-backed
`dpop.ReplayCache` for cross-instance DPoP proof single-use.

```bash
dpop/redisreplay/
├── cache.go            ReplayCache / Config / New / FailMode — SeenBefore via atomic SET NX
├── doc.go              package overview (go-redis; miniredis test-only)
└── integration_test.go //go:build integration — real Redis via Testcontainers
```

### Dependency direction (one-way, enforced)

```bash
dpop            ──▶  auth (core)  ──▶  jwx, stdlib
audit           ──▶  stdlib only                         (imports NO auth — a pure leaf)
exchange        ──▶  auth (core), audit (core)
introspection   ──▶  auth (core)  ──▶  stdlib            (no jwx — opaque tokens are never parsed)
transport/http  ──▶  auth (core), dpop
transport/mcpauth ─▶ auth (core), dpop, audit (core), MCP Go SDK   (NEVER imports exchange — no cycle)
audit/otel      ──▶  audit (core), OpenTelemetry API     (separate module; OTel SDK is test-only)
dpop/redisreplay ─▶  dpop (core), go-redis                (separate module; miniredis test-only, Testcontainers integration-tag-only)
internal/jwkstest ─▶ jwx, stdlib                          (never imports auth → no test import cycles)
```

`auth` (the core) **never** imports `dpop`, `exchange`, or any transport. `dpop` imports only `auth` and `jwx`. This keeps the dependency graph a strict DAG with `auth` at the bottom of every chain.

Multi-issuer validation lives entirely in the core: `MultiValidator` composes core `Validator`s, and both transports depend on the core `TokenValidator` interface, so a `*Validator` or a `*MultiValidator` flows through them unchanged — no new edge, no new module, zero new dependencies.

The core never imports `exchange` or any transport. `exchange` imports `auth`
(for the `*Error` shape and the raw-token/claims context helpers) but never a
transport. This keeps the dependency graph a strict DAG.

The core never imports `transport/http`. This is what makes the library usable
from non-HTTP transports (gRPC, stdio) later: a new adapter depends on the
core the same way `transport/http` does, and the core is none the wiser.

`transport/http` declares `package http` (matching its directory). Inside it,
`import "net/http"` still resolves to the standard library because a package
never qualifies its own symbols; consumers import it under an alias, e.g.
`authhttp "github.com/polyglotdev/mcp-auth-go/transport/http"`. This mirrors
`go-kit/kit/transport/http`.

## Why verifier injection replaced hard-coded claim checks

The source validator baked one product's policy into the cryptographic
validation path: it carried `BedrockClaim`/`BedrockClaimValue` constants and a
`RequiredStringClaims` config field, and enforced `claude_backend == "bedrock"`
inside `Validate`. That coupling is precisely what blocked reuse — a second
MCP server with a different (or no) backend policy could not adopt the code
without forking it.

The refactor separates **authentication** (is this a valid token from the
expected issuer/audience, unexpired, correctly signed?) from **authorization**
(is the validated caller allowed to do this?). The validator now owns only the
former. Authorization is expressed as injected `ClaimVerifier` functions:

```go
type ClaimVerifier func(ctx context.Context, tok jwt.Token) error
```

`ValidatorConfig.Verifiers []ClaimVerifier` runs in order after a successful
parse; the first error short-circuits and is returned unchanged so the
transport can map it to the right status. The library ships one ready-made
verifier, `VerifyRequiredStringClaims(map[string]string)`, which reproduces the
old behavior generically — the Atlassian gateway's policy becomes one line of
_caller_ configuration:

```go
Verifiers: []auth.ClaimVerifier{
    auth.VerifyRequiredStringClaims(map[string]string{"claude_backend": "bedrock"}),
}
```

Verifier failures return `ErrForbidden` (HTTP 403, code `forbidden`), keeping
the authn/authz distinction the middleware relies on: a bad signature is a 401;
a policy rejection is a 403. The validation core contains no reference to
`claude_backend`, `bedrock`, or any product-specific claim.

## Error model

The machine-readable `*Error` model is preserved verbatim in spirit:
`{Code, Message, DocURL, HTTPStatus, Cause}`, with `With(cause)` producing a
wrapped copy and `Is()` comparing by `Code` (so `ErrForbidden.With(detail)`
still satisfies `errors.Is(err, ErrForbidden)`). `Cause` and `HTTPStatus` are
`json:"-"`, so the wrapped diagnostic reaches logs but never the response body.

The only generalization: the Bedrock-specific `ErrBedrockRequired` (which
carried a Bedrock runbook `DocURL`) became the generic `ErrForbidden`. The
authn sentinels (`ErrMissingToken`, `ErrInvalidToken`, `ErrExpiredToken`, all 401) and the 429s (`ErrSessionLimitExceeded`, `ErrRateLimitExceeded`) are
unchanged.

## Behavior change: `Claims.Backend` removed

The source `Claims` struct had a dedicated `Backend string` field populated
from the `claude_backend` claim — a product-specific shortcut. Because the core
must not special-case any product claim, that field is gone. `claude_backend`
(and any other string-typed private claim) now flows into `Claims.Raw` via the
existing private-claims loop. **Consumers that read `claims.Backend` must read
`claims.Raw["claude_backend"]` instead.** This is the one intentional breaking
change in the typed surface; everything else (`Subject`, `Email`, `Issuer`,
`Audience`, `ExpiresAt`, `IssuedAt`, `Scopes`, `Raw`) is preserved.

## Session code — included, deliberately

`session.go` and `session_id.go` were evaluated for inclusion rather than
copied blindly. They implement a generic per-user concurrency cap with a
sliding inactivity timeout and a crypto-random id generator. There is **no**
Atlassian-, Bedrock-, or HTTP-specific behavior: the store is keyed on an
opaque user id (the Okta `sub`), the interface is small (`Open`/`Touch`/
`Close`/`Count`), and the in-memory implementation is documented as swappable
for Redis later. That makes it a reusable session utility appropriate for any
secure internal MCP server, so it ships in the core package. Its tests are
ported as-is (white-box, because they exercise the unexported `randomSessionID`).

The in-memory store is the only implementation provided; a distributed
(Redis-backed) `SessionStore` is intentionally out of scope.

## DPoP package — RFC 9449 resource-server enforcement

The `dpop` package implements the resource-server side of RFC 9449
Demonstration of Proof of Possession. It lives in the core module as a sibling
to `exchange` and `transport/http`, depending on `auth` (for the `*Error` shape
and `ErrInvalidDPoPProof`) and on `jwx` for JWS parsing. It is **never**
imported by the `auth` core: the direction is always `dpop → auth`, never the
reverse.

### Single-policy entry point — `Enforce`

`Verifier.Enforce(ctx, Input)` is the only public method a resource server
needs to call. It:

1. Checks `Input.BoundJKT` (the `cnf.jkt` from `Claims.Confirmation`) to
   decide the mode: if the field is empty, `Opportunistic` mode passes through;
   `Require` mode returns `ErrInvalidDPoPProof` immediately (no token binding =
   rejected).
2. Requires exactly one `DPoP` header value (`Input.Proofs`); zero or multiple
   proofs are rejected.
3. Calls `checkProof` which verifies the JWS signature, `typ: dpop+jwt`,
   `htm` (HTTP method), `htu` (HTTP URL, query/fragment stripped), `iat`
   freshness inside `Config.IATLeeway` (default 60 s), the `ath` binding to the
   access token (§4.3(12)), and the `jkt` thumbprint match against
   `BoundJKT` (§7.2 downgrade protection — a bound token without a matching
   proof is rejected, even if the proof itself is structurally valid).
4. Consults `ReplayCache.SeenBefore(jti, htu, exp)` to detect replayed proofs;
   `true` (already seen) causes `checkProof` to return `ErrInvalidDPoPProof`.

### `ReplayCache` seam

`ReplayCache` is an interface with one method:
`SeenBefore(jti, htu string, exp time.Time) bool`. On first sight the
implementation records the pair with its expiry and returns `false`; on a
subsequent call within the expiry window it returns `true` (a replay), and
`checkProof` maps that to `ErrInvalidDPoPProof`. The default `MemoryReplayCache`
stores `jti|htu` pairs in a mutex-guarded map with inline sweep.
`NewNopReplayCache()` disables replay protection (useful for tests that call
`Enforce` multiple times with the same proof). Callers with a multi-instance
deployment should supply the shared, Redis-backed `dpop/redisreplay` (a separate
nested module, so `go-redis` stays out of the core graph), which implements this
interface via an atomic `SET NX` and resolves a Redis outage through a mandatory
`FailMode` (`FailOpen` allow-and-alert vs `FailClosed` reject-all).

### §7.2 downgrade-attack guard

A token that carries `cnf.jkt` (i.e., `Claims.Confirmation != ""`) binds the
token to a specific DPoP key. If a client strips the `DPoP` header and presents
the bound token as a plain bearer token, the middleware detects the mismatch and
rejects the request with `ErrInvalidDPoPProof`. The check does not depend on the
proof at all — if the proof is absent but the token is bound, the request is
denied immediately (§4.3 step 1 of the check loop in `checkProof`).

### RS-issued nonce (RFC 9449 §9)

Setting `Config.Nonce` makes a valid resource-server nonce **required** on every
enforced proof (a stricter, stateless reading of the §11.3 MUST). The nonce
check sits inside `checkProof` _after_ the thumbprint match (so a forged proof
never earns a fresh nonce) and _before_ the replay check (so a nonce-less proof
is not recorded — the client retries with a new `jti`). A missing, stale, or
forged nonce returns the distinct `auth.ErrUseDPoPNonce` sentinel; `transport/http`
answers `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a
`DPoP-Nonce` header, and rotates a fresh nonce onto successful responses (§8.2,
with `Cache-Control: no-store`). The default `SignedNonce` is stateless —
`base64url(ts ‖ rand ‖ HMAC-SHA256(secret, ts‖rand))` — so any replica sharing
the secret validates it with no shared store; a valid MAC proves the server
minted it, making the embedded timestamp trustworthy. The nonce **complements**
the `ReplayCache` (it is time-window valid, not single-use, §11.1); it does not
replace `jti` tracking. Both transports support it: `transport/http` natively,
and `transport/mcpauth` through a response-wrapping middleware (see "DPoP
challenge wrapper" below) that rewrites the SDK's challenge and delivers/rotates
the `DPoP-Nonce`.

### DPoP challenge wrapper (`transport/mcpauth/challenge.go`)

The MCP Go SDK's `RequireBearerToken` hard-codes a `Bearer`-schemed
`WWW-Authenticate` and exposes no `DPoP-Nonce` hook. To reach parity with
`transport/http`, `RequireBearerToken` — when `Options.DPoP` is set — wraps the
SDK middleware with `challengeWriter`, an `http.ResponseWriter` that:

- **Rewrites the challenge.** On a DPoP enforcement failure it `Set`s a
  DPoP-schemed challenge (RFC 9449 §7.1/§9), replacing the SDK's `Bearer` value,
  and on a `use_dpop_nonce` failure emits a `DPoP-Nonce`. On a successful 2xx it
  rotates a fresh nonce (§8.2).
- **Bridges classification through the request context.** A per-request
  `challengeState` is placed on `r.Context()`; `newVerifierFunc` (which the SDK
  runs with that context) records whether the failure was DPoP and which code
  applies, and the writer reads it at `WriteHeader`. Verify runs to completion
  before the SDK writes the header, so the write and read are sequential in one
  goroutine — no race.
- **Preserves streaming.** It implements `Unwrap() http.ResponseWriter`, so the
  SDK's `http.ResponseController.Flush()` walks through to the real writer
  untouched.
- **`Cache-Control`.** The 401 challenge sets `Cache-Control: no-store` (parity
  with `transport/http`); the 2xx rotation sets `no-store` only if the handler
  set none, so the SDK's SSE `no-cache, no-transform` survives.

The wrapper is installed only when `Options.DPoP != nil`; non-DPoP consumers get
the bare SDK middleware, byte-for-byte unchanged.

### `htu` and the `BaseURL` proxy note

`Enforce` receives the URL from its caller (the transport layer), not from the
incoming request. Behind a TLS-terminating proxy the `http.Request` reflects the
internal hop (`http://` scheme, internal hostname); the client signed `htu`
against the public scheme+authority. Both `transport/http` and
`transport/mcpauth` expose a `BaseURL` configuration field: when set, the
transport substitutes `BaseURL + r.URL.Path` as the `Input.URL`, so the
client's `htu` and the server's reconstruction match.

### No-leak guarantee

Every rejection path inside `checkProof` wraps a **constant** string via
`reject(errors.New("ath mismatch"))` (or similar). The access token, the
computed `ath` preimage, and the bound `jkt` thumbprint **never** appear in
`err.Error()`, log output, or the HTTP response body. `TestNoTokenInErrorSurface`
in `dpop/example_test.go` mechanically asserts this for the two highest-risk
cases (wrong `ath` and thumbprint mismatch). `TestMiddlewareSlogNoTokenLeak` in
`transport/http` extends the guarantee to the slog-structured log record the
middleware emits on rejection.

## Exchange package — RFC 8693 token broker

The `exchange` package is a pure RFC 8693 token-exchange client. It sits in the
core module alongside `transport/http`, at the same tier but depending on `auth`
(never the reverse).

It also implements the **client** side of the Identity Assertion JWT
Authorization Grant (Cross App Access; `draft-ietf-oauth-identity-assertion-authz-grant`,
the basis of MCP Enterprise-Managed Authorization). `DownstreamTokenProvider`
runs the two-step flow: step 1 mints an ID-JAG via the generalized `Exchange`
(`RequestedTokenType=TokenTypeIDJAG`) at the enterprise IdP; step 2 redeems it
via the new RFC 7523 `jwt-bearer` `RedeemAssertion` at the Resource AS. It is
purely additive — no new package, no new module, no new dependency, and the
live-proven `Exchange` path is byte-identical for callers that set neither new
`Request` field. The MCP **server** never sees the ID-JAG; the Resource AS
validates it, and the MCP server validates the resulting access token with the
existing validators. The non-ratified draft `id-jag` URN is isolated behind the
`TokenTypeIDJAG` constant.

### Design decisions

**`ClientAuthenticator` seam.** `BasicAuth` authenticates with `client_secret_basic`.
`DPoP` wraps any `ClientAuthenticator` with an RFC 9449 proof; it holds one
long-lived ES256 key (stable `jkt`) generated at construction time. The
proof construction mirrors the pattern proven in `okta_live_test.go`.

**`Cache` seam.** `MemoryCache` is the default: a mutex-guarded map keyed on
`subject|audience|sorted-scope` (never token bytes). Entries are evicted once
`now() >= ExpiresAt - leeway`. `Get` returns a defensive copy so a caller
mutating the returned `Token` cannot corrupt the shared entry. An empty
`Subject` in the `Request` means the exchange is uncached — intentional for
service-to-service calls that don't represent a human caller.

**Per-caller isolation (HIPAA guard).** The cache key never contains the subject
token; it contains only the caller identity (`sub`), audience, and scope. Two
callers with the same audience/scope can never receive each other's tokens.

**Fail-closed `TokenForCaller`.** If `auth.RawTokenFrom(ctx)` returns nothing,
`TokenForCaller` returns `auth.ErrMissingToken` immediately and makes zero
network calls. This catches a missing auth middleware before any downstream
service sees a request.

**`mcpauth.ContextBridge()` (D1).** On the MCP SDK transport, the raw token and
claims live in the SDK's `TokenInfo.Extra` (placed there by `NewTokenVerifier`).
The `exchange` package depends only on the core context keys
(`auth.RawTokenFrom`/`auth.ClaimsFrom`). `ContextBridge()` is MCP receiving
middleware that copies from `TokenInfo.Extra` into the core keys before method
handlers run, bridging the two without any import from `exchange` to `mcpauth`.

**Secret hygiene.** The AS `error_description` is discarded by `Rejected`: it is
AS-controlled text and may echo back content from the exchange request in
misconfigured scenarios. Only the AS `error` code appears in `Message`; neither
the subject token nor the description ever enters `err.Error()`, the JSON body,
or log output.

## Audit & observability

The `audit` package is the "Logging Service" seam: a typed `audit.Event`
recorded at the two security _decision_ points and handed to a pluggable
`audit.Sink`.

**Two emission points, one vocabulary.** `transport/mcpauth.ToolGate` emits a
`tool_call` event (granted/denied, with the tool name and the denial reason
code) per `tools/call`; `exchange.Exchange` emits a `token_exchange` event
(granted/denied/error, with the caller `sub` and target audience) per RFC 8693
exchange — covering the cache-hit, success, and failure paths. The sink is
optional on both (`nil` ⇒ zero overhead), like every other seam.

**Three-tier field partition (enforced in code).** The `Event` partitions its
fields by sensitivity, and two accessors enforce the partition so a telemetry
sink physically cannot leak:

- **Tier 1** — `action`, `outcome`, `reason_code`: bounded and not
  client-controlled → safe as metric **labels** (`Event.MetricLabels()`) and as
  span attributes.
- **Tier 2** — `tool`, `subject`, `issuer`, `audience`, `scopes`: PHI-safe but
  client-controlled or high-cardinality → span attributes only
  (`Event.TraceAttributes()`), **never** metric labels (so an unauthenticated
  caller's arbitrary tool name cannot blow up `mcp.tool.calls` cardinality).
- **Tier 3** — `email`: PII → compliance/BAA sinks only; never reaches
  `MetricLabels`/`TraceAttributes`.

**`reason_code` is always a code.** It is derived via
`errors.As → *auth.Error.Code` (fallback `"forbidden"`), never `err.Error()` /
`Message` / `Cause` — so a built-in authorizer's input-bearing cause
(`claim "x" != "secret"`) can never reach a label.

**Best-effort delivery.** `Sink.Record(ctx, Event)` returns no error; the sink
owns durability. `NewSlogSink` is the default compliance sink (logs the full
event including `Email` — point it at BAA-covered storage; panics on a nil
logger). `NewMultiSink` fans out (place the durable compliance sink first);
`NewNopSink` is the opt-out.

**OTel without polluting core.** `audit/otel` (a separate nested module, the
OpenTelemetry **API** only — the SDK is test-only) maps each event to an Int64
counter (`mcp.tool.calls` / `mcp.broker.exchanges`, bounded labels) and a span
event on the caller's active span (`trace.SpanFromContext`, PHI-safe attributes,
never `Email`). The `MeterProvider` is injected (defaults to the OTel global); no
`TracerProvider` is needed since events attach to the active span. The core
module never imports OpenTelemetry.

## Testing structure

| Test                                                      | Package                                      | Rationale                                                                                                                              |
| --------------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `errors_test.go`, `verifier_test.go`, `validator_test.go` | `auth_test` (black-box)                      | exercise the public API as a consumer would; can import `internal/jwkstest` without an import cycle                                    |
| `session_test.go`                                         | `auth` (white-box)                           | tests the unexported `randomSessionID`                                                                                                 |
| `dpop/*_test.go`                                          | `dpop` (white-box) + `dpop_test` (black-box) | white-box: `checkProof`, replay, mode logic; black-box: `ExampleNewVerifier`, no-leak assertion, skip-guarded live Okta test           |
| `transport/http/middleware_test.go`                       | `http` (white-box)                           | tests the unexported `extractBearer` / `setRetryAfter`; DPoP path tests (bound+valid, bound+no-proof, opportunistic, require, BaseURL) |
| `transport/http/metadata_test.go`                         | `http` (white-box)                           | shares the package's `discardLogger` helper                                                                                            |

`internal/jwkstest` exists because both the core and the transport test suites
need to mint signed JWTs against a live JWKS endpoint. It imports only `jwx`
and the standard library (never `auth`), so white-box tests can use it without
creating an import cycle.

## What was intentionally excluded

- **The Atlassian gateway migration itself.** This module is standalone; the
  gateway is not modified. See the migration notes below.
- **A `RequiredStringClaims` compatibility shim.** There are no external
  consumers of this module yet, so the clean break to `Verifiers` is preferred
  over carrying a deprecated field. The migration is mechanical (below).
- **New transports (gRPC, stdio)** and a **distributed session store** — the
  layout makes both possible; neither is built here.

## Gateway migration notes (for `mcp-atlassian-go`)

When the Atlassian gateway adopts this module, the change is mechanical:

1. Replace `import ".../internal/auth"` with
   `import auth "github.com/polyglotdev/mcp-auth-go"` and
   `import authhttp "github.com/polyglotdev/mcp-auth-go/transport/http"`.
2. Move HTTP usages (`MiddlewareConfig`, `RateLimiter`, `MetadataHandler`,
   `ProtectedResourceMetadata`, `MetadataPath`) to the `authhttp` alias.
3. Define the Bedrock policy in the gateway (it is product policy, not library
   code) and pass it as a verifier:

   ```go
   const bedrockClaim, bedrockValue = "claude_backend", "bedrock"
   cfg.Verifiers = []auth.ClaimVerifier{
       auth.VerifyRequiredStringClaims(map[string]string{bedrockClaim: bedrockValue}),
   }
   ```

4. Replace any read of `claims.Backend` with `claims.Raw["claude_backend"]`.
5. Replace `errors.Is(err, auth.ErrBedrockRequired)` checks with
   `errors.Is(err, auth.ErrForbidden)`. If the gateway needs the Bedrock
   runbook URL back in the 403 body, construct a project-specific `*auth.Error`
   (the type is exported) or wrap with a verifier that returns one.

Validation semantics (signature, `iss`/`aud`/`exp`/`nbf`, clock skew, the
missing/invalid/expired distinction, the JWKS background-refresh model) are
unchanged, so no behavioral re-testing of those paths is required beyond the
ported suite.
