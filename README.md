# mcp-auth-go

[![CI](https://github.com/polyglotdev/mcp-auth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/polyglotdev/mcp-auth-go/actions/workflows/ci.yml)
[![CodeQL](https://github.com/polyglotdev/mcp-auth-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/polyglotdev/mcp-auth-go/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/polyglotdev/mcp-auth-go/badge)](https://scorecard.dev/viewer/?uri=github.com/polyglotdev/mcp-auth-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/polyglotdev/mcp-auth-go.svg)](https://pkg.go.dev/github.com/polyglotdev/mcp-auth-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/polyglotdev/mcp-auth-go)](https://goreportcard.com/report/github.com/polyglotdev/mcp-auth-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8.svg)](go.mod)

Transport-agnostic Okta-JWT authentication and authorization for secure
internal MCP services.

> The Go Reference and Go Report Card badges activate once the module is pushed
> to `github.com/polyglotdev/mcp-auth-go`.

- **Validates** Okta-issued JWTs against a JWKS endpoint (signature, `iss`,
  `aud`, `exp`/`nbf`, clock skew) with a background-refreshing key cache.
- **Typed claims** + context helpers, so handlers never touch `jwx` internals.
- **Pluggable authorization** via injected `ClaimVerifier`s — the library has
  no built-in product policy.
- **HTTP adapter** (`transport/http`) with bearer-token middleware, RFC 6750
  `WWW-Authenticate` challenges, optional per-user rate limiting, and an
  RFC 9728 Protected Resource Metadata handler.
- **MCP Go SDK adapter** (`transport/mcpauth`) — a drop-in `TokenVerifier` for
  the official MCP Go SDK's bearer middleware, shipped as a separate nested
  module so the SDK never enters the core module's graph.
- **Composable authorization** — `Authorizer` policies (`AllOf`/`AnyOf`/
  `HasScopes`/`HasAnyScope`/`HasClaim`) and a `ToolGate` that enforces them per
  MCP tool, failing closed for unauthenticated or (optionally) unlisted tools.
- **Audit & OpenTelemetry** — a pluggable `audit.Sink` records every tool-call
  authorization and token-exchange decision behind a PHI/PII-aware field
  partition; an optional `audit/otel` adapter (a separate module) emits metrics +
  trace span events without pulling OpenTelemetry into the core.

The core package is transport-neutral; the HTTP package depends on it, never
the reverse. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and the
authentication-vs-authorization split.

## Packages

Everything except three opt-in adapters lives in the **core module**
(`go get github.com/polyglotdev/mcp-auth-go`), whose only third-party
dependency is `jwx/v2`. The three adapters that pull a heavier dependency each
ship as a **separate nested module** (the last three rows), so that dependency
never enters the core graph unless you import the adapter. Paths are relative to
the module root `github.com/polyglotdev/mcp-auth-go`.

| Import path | Purpose | Added dependency |
| --- | --- | --- |
| `.` | JWT/JWKS validation, typed `Claims`, authorizers, sessions | `jwx/v2` |
| `transport/http` | `net/http` middleware, RFC 9728 metadata | none |
| `introspection` | RFC 7662 opaque-token validation | none |
| `dpop` | RFC 9449 proof-of-possession | none |
| `exchange` | RFC 8693 exchange, Cross App Access client | none |
| `audit` | the `audit.Sink` seam and `Event` | none |
| `transport/mcpauth` | MCP Go SDK adapter, `ToolGate` | MCP Go SDK |
| `audit/otel` | OpenTelemetry audit sink | OpenTelemetry API |
| `dpop/redisreplay` | Redis-backed DPoP replay cache | go-redis |

## Install

```sh
go get github.com/polyglotdev/mcp-auth-go
```

Requires Go 1.26+. The only third-party dependency is
[`github.com/lestrrat-go/jwx/v2`](https://github.com/lestrrat-go/jwx).

## Quick start

This uses the standard library `net/http` middleware. Building on the official
MCP Go SDK instead? See [Use with the official MCP Go SDK](#use-with-the-official-mcp-go-sdk).

```go
package main

import (
  "context"
  "log/slog"
  "net/http"
  "os"

  auth "github.com/polyglotdev/mcp-auth-go"
  authhttp "github.com/polyglotdev/mcp-auth-go/transport/http"
)

func main() {
  ctx := context.Background()
  logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

  // The validator owns a JWKS cache; the initial fetch is synchronous so a
  // misconfigured issuer fails fast at startup.
  v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
    JWKSURL:  "https://acme.okta.com/oauth2/aus123/v1/keys",
    Issuer:   "https://acme.okta.com/oauth2/aus123",
    Audience: "https://mcp.internal.acme.com",
    // Authorization policy is injected, not built in. This one requires a
    // claude_backend=bedrock claim; supply your own as needed.
    Verifiers: []auth.ClaimVerifier{
      auth.VerifyRequiredStringClaims(map[string]string{"claude_backend": "bedrock"}),
    },
  })
  if err != nil {
    logger.Error("auth init failed", slog.Any("err", err))
    os.Exit(1)
  }

  mcp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims := auth.MustClaims(r.Context()) // panics if middleware is bypassed
    logger.Info("request", slog.String("sub", claims.Subject))
    w.WriteHeader(http.StatusOK)
  })

  mw := authhttp.MiddlewareConfig{
    Validator: v,
    Logger:    logger,
    // RFC 9728 pointer echoed in the WWW-Authenticate challenge on a 401,
    // so a client can discover the authorization server.
    ResourceMetadataURL: "https://mcp.internal.acme.com" + authhttp.MetadataPath,
  }.Middleware()

  mux := http.NewServeMux()
  mux.Handle("/mcp", mw(mcp))
  mux.HandleFunc(authhttp.MetadataPath, authhttp.MetadataHandler(logger, authhttp.ProtectedResourceMetadata{
    Resource:               "https://mcp.internal.acme.com",
    AuthorizationServers:   []string{"https://acme.okta.com/oauth2/aus123"},
    BearerMethodsSupported: []string{"header"},
    ScopesSupported:        []string{"mcp:read", "mcp:write"},
  }))

  if err := http.ListenAndServe(":8080", mux); err != nil {
    logger.Error("server stopped", slog.Any("err", err))
  }
}
```

When the MCP endpoint is mounted under a sub-path (for example `/mcp`), serve its
metadata at the RFC 9728 section 3 path-aware location returned by
`authhttp.MetadataPathFor("/mcp")` rather than the root `MetadataPath`, and point
`ResourceMetadataURL` at that same location.

## Multi-issuer validation

Need one resource server to accept tokens from **more than one** issuer — an IdP
migration, a multi-tenant gateway, or a user-AS + service-AS split? Wrap N issuer
configs in a `MultiValidator`. Each issuer is a full `ValidatorConfig` (its own
JWKS, `iss`, `aud`, and verifiers); the token's `iss` selects which one applies,
then that issuer's `Validator` runs the real signature + audience + verifier
checks.

```go
mv, err := auth.NewMultiValidator(ctx, auth.MultiValidatorConfig{
  Issuers: []auth.ValidatorConfig{
    { // outgoing IdP (kept during a cutover window)
      JWKSURL:  "https://old.okta.com/oauth2/aus_old/v1/keys",
      Issuer:   "https://old.okta.com/oauth2/aus_old",
      Audience: "https://mcp.internal.acme.com",
    },
    { // incoming IdP
      JWKSURL:   "https://new.okta.com/oauth2/aus_new/v1/keys",
      Issuer:    "https://new.okta.com/oauth2/aus_new",
      Audience:  "https://mcp.internal.acme.com",
      Verifiers: []auth.ClaimVerifier{auth.RequireScopes("mcp:read")},
    },
  },
})
if err != nil { /* ... */ }

// Same transports — MultiValidator satisfies the TokenValidator interface that
// transport/http and transport/mcpauth both accept.
mw := authhttp.MiddlewareConfig{Validator: mv, Logger: logger}.Middleware()
// or: mcpauth.RequireBearerToken(mv, opts)
```

Both `*Validator` and `*MultiValidator` implement the one-method `TokenValidator`
interface (`Validate(ctx, bearer) (*Claims, error)`), so existing single-issuer
wiring compiles unchanged — the transports accept either.

**Routing is by exact `iss` match** (no canonicalization — configure the
byte-identical `iss` the IdP emits, exactly as for a single `Validator`). A token
whose `iss` is unknown, missing, or unparseable **fails closed** with
`ErrInvalidToken` and triggers no JWKS fetch. Each issuer keeps its **own**
audience check, so a token minted for one tenant cannot be replayed against
another. Configured issuers **must not share signing key material** (routing is
by `iss`; a shared key would let its holder mint a token accepted under either
issuer).

## Opaque-token introspection (RFC 7662)

Some authorization servers issue **opaque** access tokens — random strings with
no locally verifiable claims — by policy, or to enable instant revocation. There
is no JWKS to fetch and no signature to check; the only way to validate one is to
**ask the issuer** via its RFC 7662 introspection endpoint. The `introspection`
package does exactly that, and produces the **same `*auth.Claims`** the JWT path
does, so it drops into the same transports.

```go
iv, err := introspection.NewValidator(introspection.Config{
  IntrospectionURL: "https://acme.okta.com/oauth2/default/v1/introspect",
  ClientAuth:       introspection.BasicAuth{ClientID: id, ClientSecret: secret},
  Issuer:           "https://acme.okta.com/oauth2/default",
  Audience:         "https://mcp.internal.acme.com",
  // Cache: introspection.NewMemoryCache(time.Now, 30*time.Second), // opt-in
})
if err != nil { /* ... */ }

// Same transports — introspection.Validator satisfies the TokenValidator
// interface that transport/http and transport/mcpauth both accept.
mw := authhttp.MiddlewareConfig{Validator: iv, Logger: logger}.Middleware()
// or: mcpauth.RequireBearerToken(iv, opts)
```

The validator POSTs the token (with the configured client authentication) to the
endpoint, then **confirms the returned `iss` and `aud` itself** — by exact match,
failing closed if either is absent (an introspection endpoint can report a token
minted for a _different_ resource as `active`, so the resource server must verify
the audience). The opaque token is treated as a secret: it never appears in a
log, an error, or an un-hashed cache key.

Authenticate to the endpoint with `introspection.BasicAuth` (client_secret_basic)
or `introspection.FormPost` (client_secret_post); both satisfy the required
`ClientAuth` field.

**Caching is opt-in and off by default.** With no `Cache`, every request
introspects, so a token revoked at the authorization server is rejected
immediately. A `Cache` trades that immediacy for throughput; entries are bounded
by the response `exp` (RFC 7662 §4: a response must not be cached beyond its
`exp`), and a response without `exp` is never cached.

> **Operator requirement:** the introspection endpoint **must return `iss` and
> `aud`**. If it does not, the validator cannot confirm the audience and rejects
> every token (fail closed) — by design. `Email`/`Raw` from introspection carry
> the authorization server's trust level (no local signature); use `Subject` as
> the identity and never authorize on `Email`.

## Use with the official MCP Go SDK

Building on [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk)?
The `transport/mcpauth` adapter turns a `Validator` into the SDK's
`auth.TokenVerifier`, so your SDK server gets JWKS validation **and the RFC 8707
audience check** (which the SDK does not perform) in one line.

It is a **separate nested module**, so the SDK dependency only reaches code that
opts in:

```sh
go get github.com/polyglotdev/mcp-auth-go/transport/mcpauth
```

```go
import (
  auth "github.com/polyglotdev/mcp-auth-go"
  "github.com/polyglotdev/mcp-auth-go/transport/mcpauth"
  "github.com/modelcontextprotocol/go-sdk/mcp"
)

v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
  JWKSURL:  "https://acme.okta.com/oauth2/aus123/v1/keys",
  Issuer:   "https://acme.okta.com/oauth2/aus123",
  Audience: "https://mcp.internal.acme.com",
})
// handle err

server := mcp.NewServer(&mcp.Implementation{Name: "acme-mcp", Version: "1.0.0"}, nil)
handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)

// Required scopes go in Options.Scopes (not on the Validator) so a shortfall
// gets the SDK's RFC 6750 insufficient_scope 403 challenge.
secured := mcpauth.RequireBearerToken(v, &mcpauth.Options{
  ResourceMetadataURL: "https://mcp.internal.acme.com/.well-known/oauth-protected-resource",
  Scopes:              []string{"mcp:read"},
})(handler)

http.Handle("/mcp", secured)
```

Prefer `mcpauth.NewTokenVerifier(v)` if you'd rather call the SDK's
`auth.RequireBearerToken` yourself.

**Status mapping.** The SDK's `TokenVerifier` contract has a single failure
path — an error that unwraps to its `ErrInvalidToken` (HTTP 401). This adapter
therefore maps **every** validation failure (bad signature, wrong audience,
expired, _and_ any `ClaimVerifier` rejection) to **401**, exposing only the
public message. A **403** is reachable only via the SDK's own scope check, so
enforce required scopes through `Options.Scopes` rather than `auth.RequireScopes`
on the `Validator`.

**Per-tool authorization.** Bearer scopes gate the whole endpoint; `ToolGate`
gates individual tools. It runs as MCP receiving middleware and authorizes each
`tools/call` against a per-tool policy built from composable `auth.Authorizer`s:

```go
server.AddReceivingMiddleware(mcpauth.ToolGate{
    Policies: map[string]auth.Authorizer{
        "write_prescription": auth.AllOf(
            auth.HasScopes("mcp:write"),
            auth.HasClaim("role", "clinician"),
        ),
    },
    // Default: auth.DenyAll,  // fail closed: every tool then needs a policy
}.Middleware())
```

Unlisted tools are allowed by default (they still required a valid token); set
`Default: auth.DenyAll` to fail closed. A denied call is rejected with a JSON-RPC
error **before the tool runs**, and a call with no authenticated caller is denied.
`ToolGate` also **filters `tools/list`** so a caller only discovers the tools it
may use — unauthorized tools' names and schemas aren't disclosed. Read the caller
inside a tool handler with `mcpauth.ClaimsFromContext(ctx)`.

## DPoP (RFC 9449 Proof of Possession)

The `dpop` package enforces RFC 9449 on the resource-server side. It verifies
that the `DPoP` proof header is correctly signed, bound to the access token, and
matches the request method and URL — protecting against token theft even if a
bearer token is intercepted.

```go
import (
    auth "github.com/polyglotdev/mcp-auth-go"
    authhttp "github.com/polyglotdev/mcp-auth-go/transport/http"
    "github.com/polyglotdev/mcp-auth-go/dpop"
)

v, err := auth.NewValidator(ctx, auth.ValidatorConfig{ /* ... */ })
// handle err

dv := dpop.NewVerifier(dpop.Config{
    // Opportunistic (default): enforce only for DPoP-bound tokens (cnf.jkt set).
    // Unbound tokens pass through as plain bearers.
    // Mode: dpop.Require,   // mandate DPoP binding for every token
    // IATLeeway: 30 * time.Second, // tighten or loosen the proof freshness window
})

mw := authhttp.MiddlewareConfig{
    Validator: v,
    Logger:    logger,
    // Attach the DPoP verifier. Enforcement runs after a successful Validate,
    // using the token's cnf.jkt and the request's DPoP header.
    DPoP: dv,
    // Behind a TLS-terminating proxy the request arrives over HTTP internally,
    // but the client signed htu against the public HTTPS URL. Set BaseURL to
    // the public scheme+authority so the check matches.
    // BaseURL: "https://mcp.example.com",
}.Middleware()
```

**MCP Go SDK transport.** Pass `DPoP` through `Options`:

```go
secured := mcpauth.RequireBearerToken(v, &mcpauth.Options{
    Scopes: []string{"mcp:read"},
    DPoP:   dv,
    // BaseURL: "https://mcp.example.com", // TLS proxy note: same as above
})(handler)
```

Note: `transport/mcpauth` wraps the SDK response so a DPoP failure is answered
with the same `DPoP`-schemed `WWW-Authenticate` challenge described below — and a
`DPoP-Nonce` header when a nonce is configured. A bare `NewTokenVerifier` cannot
shape the response and falls back to the SDK's `Bearer` challenge, so use
`RequireBearerToken` for DPoP parity.

**Require mode.** Set `Mode: dpop.Require` if every client must present a
DPoP-bound token. Tokens without `cnf.jkt` are rejected immediately — no bearer
fallback.

**`WWW-Authenticate` scheme (both transports).** When DPoP enforcement fails,
the middleware challenges the client with `DPoP realm="mcp",
error="invalid_dpop_proof"` (RFC 9449 §7.1), rather than the usual `Bearer`
scheme, so compliant clients know to re-present a fresh proof.

**RS-issued nonce (both transports).** Set `Config.Nonce` to a `SignedNonce`
(the stateless default) to require a fresh, server-issued nonce on every proof
(RFC 9449 §9). A proof without a valid nonce is answered with `401` +
`WWW-Authenticate: DPoP error="use_dpop_nonce"` + a `DPoP-Nonce` header; the
client retries with that nonce, and successful responses rotate a fresh one.
Use one secret (≥ 32 bytes) shared across replicas — no shared store is needed.
Enabling it is a posture change: clients must support the `use_dpop_nonce` retry
and each pays one cold-start round-trip. The MCP SDK transport supports it too,
through `RequireBearerToken` (which wraps the response to emit and rotate the
`DPoP-Nonce`); a bare `NewTokenVerifier` cannot, so use `RequireBearerToken`.

```go
secret := loadSharedSecret() // >= 32 bytes, identical across replicas
ns, _ := dpop.NewSignedNonce(secret, 2*time.Minute)
dv := dpop.NewVerifier(dpop.Config{Nonce: ns})
```

**Replay protection.** The default `MemoryReplayCache` stores `jti+htu` pairs
inside the process, so it cannot catch a proof replayed against a _different_
instance behind a load balancer. For multi-instance deployments, supply the
shared, Redis-backed `dpop/redisreplay` — a separate nested module, so `go-redis`
stays out of the core module's dependency graph:

```go
import "github.com/polyglotdev/mcp-auth-go/dpop/redisreplay"

replay, _ := redisreplay.New(redisreplay.Config{
    Client:   rdb,                  // caller-owned redis.UniversalClient
    FailMode: redisreplay.FailOpen, // on a Redis outage: allow + alert (degrades to
                                    // freshness-window-only). FailClosed rejects all bound traffic.
    Logger:   logger,              // recommended whenever FailOpen is used
})
dv := dpop.NewVerifier(dpop.Config{ReplayCache: replay})
```

## RFC 8693 Token Exchange (broker)

The `exchange` package lets a validated MCP request exchange the caller's
inbound token for a downstream service token, scoped to a specific audience.
No new third-party dependencies — it uses the `jwx` library already present in
the core module.

```go
import (
    auth "github.com/polyglotdev/mcp-auth-go"
    "github.com/polyglotdev/mcp-auth-go/exchange"
)

// At startup: build the exchanger once (it holds the DPoP key and token cache).
d, err := exchange.NewDPoP(exchange.BasicAuth{
    ClientID:     os.Getenv("SVC_CLIENT_ID"),
    ClientSecret: os.Getenv("SVC_CLIENT_SECRET"),
})
// handle err
ex, err := exchange.NewExchanger(exchange.Config{
    TokenURL:   "https://acme.okta.com/oauth2/default/v1/token",
    ClientAuth: d,
})
// handle err

// Inside a tool handler: exchange the caller's inbound token for a downstream
// token. Requires the auth middleware (HTTP transport) or
// mcpauth.ContextBridge() (MCP SDK transport) to have run first.
func myToolHandler(w http.ResponseWriter, r *http.Request) {
    tok, err := ex.TokenForCaller(r.Context(), "api://downstream-service", "svc:read")
    if err != nil {
        // auth.ErrMissingToken → middleware was bypassed (fail closed)
        // exchange.ErrExchangeRejected → AS rejected the exchange
        // exchange.ErrExchangeUnavailable → AS unreachable
        http.Error(w, "downstream auth failed", http.StatusBadGateway)
        return
    }
    // tok.AccessToken is the downstream Bearer token. Never log it.
    _ = tok
}
```

**MCP SDK transport.** Install `mcpauth.ContextBridge()` as MCP receiving
middleware so `auth.RawTokenFrom` resolves inside tool handlers:

```go
server.AddReceivingMiddleware(mcpauth.ContextBridge())
```

`ContextBridge` copies the validated claims and raw bearer token from the SDK's
`TokenInfo` into the core context keys (`auth.WithClaims` / `auth.WithRawToken`)
that `TokenForCaller` reads. It is a no-op for unauthenticated requests and
requires no import of `exchange` in `mcpauth` (no cycle).

## Cross App Access — ID-JAG client (`DownstreamTokenProvider`)

The `exchange` package also implements the **client** side of the
[Identity Assertion JWT Authorization Grant](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant)
(Cross App Access; the basis of MCP's Enterprise-Managed Authorization). A
`DownstreamTokenProvider` takes a caller's enterprise identity assertion and
returns a downstream access token through the standard two-step flow:

1. **Mint the ID-JAG** — an RFC 8693 token exchange at the **enterprise IdP**
   (`requested_token_type=urn:ietf:params:oauth:token-type:id-jag`), exchanging
   an OIDC ID Token / SAML2 assertion / refresh token for an ID-JAG scoped to a
   downstream Resource Authorization Server.
2. **Redeem the ID-JAG** — an RFC 7523 `jwt-bearer` grant at the **Resource
   Authorization Server**, yielding a normal access token audience-restricted to
   the target resource.

```go
p, err := exchange.NewDownstreamProvider(exchange.DownstreamConfig{
    IDP: exchange.Endpoint{ // step 1: the enterprise IdP token endpoint
        TokenURL:   "https://idp.example.com/oauth2/v1/token",
        ClientAuth: exchange.BasicAuth{ClientID: idpID, ClientSecret: idpSecret},
    },
    ResourceAS: exchange.Endpoint{ // step 2: the Resource AS token endpoint
        TokenURL:   "https://acme.chat.example/oauth2/token",
        ClientAuth: exchange.BasicAuth{ClientID: rasID, ClientSecret: rasSecret},
    },
    Audience: "https://acme.chat.example/", // the Resource AS issuer identifier
    Resource: "https://api.chat.example/",  // the target resource (MCP server) id
    Scope:    []string{"chat.read", "chat.history"},
    // Cache: exchange.NewMemoryCache(time.Now, 30*time.Second), // opt-in
})
// handle err

tok, err := p.Provide(ctx, exchange.ProvideRequest{
    SubjectAssertion: callerIDToken, // an OIDC ID Token from the enterprise IdP
    Subject:          callerSub,     // explicit cache-key identity — never parsed from the token
})
// tok.AccessToken is the downstream access token. Never log it.
```

**Role boundary.** This is the client/requesting-app side. The MCP **server**
never receives the ID-JAG — the Resource Authorization Server validates it and
the MCP server validates the _resulting access token_ with the usual
`auth.Validator` / `introspection.Validator` (including the RFC 8707 audience
check the `resource` restriction relies on).

**Security notes.** The two `Endpoint`s are different trust domains — their
`ClientAuth` **must use distinct credentials**. The subject assertion, the
ID-JAG, and the issued token are secrets: never logged, never in an error cause,
never a cache key (the cache keys on the explicit `Subject`). DPoP works per leg
via `Endpoint.ClientAuth = exchange.NewDPoP(...)`. The `id-jag` token-type is
from a **non-ratified IETF draft**, isolated behind the `exchange.TokenTypeIDJAG`
constant.

## Audit & observability

Record every security decision — each `tools/call` authorization and each
RFC 8693 token exchange — through a pluggable `audit.Sink`. Wire it onto the
`ToolGate` and the `Exchanger`; a `nil` sink is a zero-overhead no-op.

```go
import (
    "github.com/polyglotdev/mcp-auth-go/audit"
    otelaudit "github.com/polyglotdev/mcp-auth-go/audit/otel"
)

// Fan out to a compliance log AND OpenTelemetry. The compliance sink goes FIRST
// (a panic in a later sink must not drop the durable record).
otelSink, _ := otelaudit.NewSink(otelaudit.Config{}) // defaults to the OTel global MeterProvider
sink := audit.NewMultiSink(
    audit.NewSlogSink(baaLogger), // full event incl. Email -> BAA-covered storage
    otelSink,                     // metrics + span events, PHI-free
)

gate := mcpauth.ToolGate{Policies: policies, Default: auth.DenyAll, Audit: sink}
ex, _ := exchange.NewExchanger(exchange.Config{TokenURL: tokenURL, ClientAuth: d, Audit: sink})
```

**PHI/PII-aware by construction.** The `audit.Event` partitions its fields so a
telemetry sink cannot leak: only bounded, non-client-controlled values
(`action`, `outcome`, `reason_code`) become **metric labels**; `tool` / `subject`
/ `audience` / `scopes` are span attributes only (PHI-safe, but kept out of labels
so an attacker can't blow up cardinality); `email` reaches compliance sinks only,
never OpenTelemetry. `NewSlogSink` is the default compliance sink (logs the full
event including `Email` — point it at BAA-covered storage); `NewNopSink` is the
opt-out.

**OTel stays out of the core.** `audit/otel` is a separate nested module that
compiles against the OpenTelemetry **API** only (the SDK is a test dependency),
so importing the core never pulls in OpenTelemetry:

```sh
go get github.com/polyglotdev/mcp-auth-go/audit/otel
```

It emits the `mcp.tool.calls` / `mcp.broker.exchanges` counters and a span event
on the caller's active span. The `MeterProvider` is injected (defaulting to the
OTel global); no `TracerProvider` is needed.

## Per-user rate limiting and sessions

The HTTP middleware can rate-limit per authenticated user. Set
`MiddlewareConfig.RateLimiter` to any implementation of the one-method
`authhttp.RateLimiter` interface; the middleware keys it on the token's
`Subject`, and a rejection returns `ErrRateLimitExceeded` (429) with a
`Retry-After` header. The library ships the interface, not an implementation, so
you plug in your own (a token bucket, a Redis counter, or a fake in tests)
without the middleware depending on it. `MiddlewareConfig.Scopes` advertises the
scopes your verifiers require in the RFC 6750 `scope` challenge on an
`insufficient_scope` 403.

```go
mw := authhttp.MiddlewareConfig{
  Validator:   v,
  Logger:      logger,
  RateLimiter: myLimiter, // Allow(key string, now time.Time) (bool, time.Duration)
  Scopes:      []string{"mcp:read", "mcp:write"},
}.Middleware()
```

Separately, the core package offers a transport-neutral per-user concurrency cap.
`auth.NewMemorySessionStore` bounds how many sessions a single `Subject` may hold
open at once and applies a sliding inactivity timeout; opening one past the cap
returns `ErrSessionLimitExceeded` (429). It is not authentication (every request
must still validate its bearer token); it only bounds concurrency, and you wire
it into your own handler rather than the middleware applying it automatically.

```go
store := auth.NewMemorySessionStore(auth.SessionConfig{
  MaxConcurrentPerUser: 3,
  Timeout:              30 * time.Minute,
}, nil) // nil idFn => cryptographically-random session ids

id, err := store.Open(claims.Subject, time.Now())
// errors.Is(err, auth.ErrSessionLimitExceeded) => the user is at the cap
```

## Error model

Failures are typed `*auth.Error` values that map to HTTP statuses and stay
distinguishable with `errors.Is`:

| Sentinel                  | Code                     | Status | Meaning                                                |
| ------------------------- | ------------------------ | ------ | ------------------------------------------------------ |
| `ErrMissingToken`         | `missing_token`          | 401    | no/!Bearer Authorization header                        |
| `ErrInvalidToken`         | `invalid_token`          | 401    | bad signature, `iss`/`aud`, malformed, JWKS down       |
| `ErrExpiredToken`         | `expired_token`          | 401    | `exp` in the past                                      |
| `ErrInvalidDPoPProof`     | `invalid_dpop_proof`     | 401    | DPoP proof missing, invalid, replayed, or key mismatch |
| `ErrForbidden`            | `forbidden`              | 403    | valid token, but a verifier rejected it                |
| `ErrInsufficientScope`    | `insufficient_scope`     | 403    | valid token, missing a required scope                  |
| `ErrSessionLimitExceeded` | `session_limit_exceeded` | 429    | per-user concurrency cap hit                           |
| `ErrRateLimitExceeded`    | `rate_limit_exceeded`    | 429    | per-user rate limit hit                                |

The wrapped diagnostic `Cause` is logged but never serialized into the response
body.

## Development

```sh
make check              # gofmt + vet + lint + race tests (the full gate)
go test -race ./...     # full suite, race detector on
golangci-lint run ./... # lint (config in .golangci.yml)
```

## License

[MIT](LICENSE) — use it freely, commercially or otherwise, free of charge. The
only condition is preserving the copyright and permission notice.
