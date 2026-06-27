package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
)

// RateLimiter is the small surface the middleware needs from a rate-limiting
// package. Defining it here keeps the dependency one-way: callers substitute
// their own implementation (or a fake in tests) without this package
// importing theirs.
type RateLimiter interface {
	// Allow reports whether the key may proceed at time now, and if not, how
	// long the caller should wait before retrying.
	Allow(key string, now time.Time) (bool, time.Duration)
}

// MiddlewareConfig wires the validator, an optional rate limiter, and the
// time source (injected for deterministic tests) into the HTTP middleware.
type MiddlewareConfig struct {
	// Validator is required. It accepts a *auth.Validator (single issuer) or a
	// *auth.MultiValidator (a configured set of trusted issuers, routed by iss);
	// it owns the JWKS cache(s).
	Validator auth.TokenValidator

	// RateLimiter is optional. If nil, no per-user rate limiting is applied
	// (the server is still token-protected).
	RateLimiter RateLimiter

	// Logger is required -- failure modes are logged at warn/info level.
	// Never log token contents or Email -- only Subject + error code.
	Logger *slog.Logger

	// ResourceMetadataURL, when set, is echoed in the WWW-Authenticate
	// challenge as the RFC 9728 resource_metadata parameter, so a client can
	// discover this resource's metadata (and its authorization server) from a
	// 401 or 403. Set it to the absolute URL of the
	// /.well-known/oauth-protected-resource document. The MCP authorization
	// spec expects this pointer on 401 responses.
	ResourceMetadataURL string

	// Scopes, when set, are advertised in the WWW-Authenticate challenge on an
	// insufficient_scope rejection (the RFC 6750 scope parameter), so a client
	// learns which scopes to request for step-up authorization. Set it to the
	// scopes your verifiers require (see auth.RequireScopes).
	Scopes []string

	// Now returns the wall clock. Defaults to time.Now if nil.
	Now func() time.Time

	// DPoP, when set, enforces RFC 9449 proof-of-possession per its Mode after
	// a successful Validate. nil ⇒ no DPoP enforcement (the default behavior).
	DPoP *dpop.Verifier

	// BaseURL, when set, supplies the public scheme+authority for the htu used
	// in DPoP enforcement (the path comes from the request). Set it behind a
	// TLS-terminating proxy, where r.Host/r.TLS reflect the internal hop and
	// would mismatch the client-signed htu. Empty ⇒ htu is reconstructed from
	// the request.
	BaseURL string
}

// Middleware returns an http.Handler middleware that enforces:
//  1. Authorization: Bearer header presence
//  2. Token signature, exp/nbf/iat, iss/aud
//  3. Any authorization verifiers configured on the Validator
//  4. Per-user rate limit (if RateLimiter is non-nil)
//
// On success, the request's context carries the verified Claims (read them
// with auth.ClaimsFrom inside downstream handlers). On failure, a structured
// JSON error is written with the appropriate HTTP status and, where
// applicable, a Retry-After header.
func (cfg MiddlewareConfig) Middleware() func(http.Handler) http.Handler {
	if cfg.Validator == nil {
		panic("auth/http: MiddlewareConfig.Validator is required") // construction-time guard; not a request handler
	}
	if cfg.Logger == nil {
		panic("auth/http: MiddlewareConfig.Logger is required") // construction-time guard; not a request handler
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer, err := extractBearer(r)
			if err != nil {
				cfg.writeAuthError(w, err)
				return
			}

			claims, err := cfg.Validator.Validate(r.Context(), bearer)
			if err != nil {
				cfg.writeAuthError(w, err)
				return
			}

			if cfg.DPoP != nil {
				derr := cfg.DPoP.Enforce(r.Context(), dpop.Input{
					Proofs:      r.Header.Values("DPoP"),
					Method:      r.Method,
					URL:         requestURL(r, cfg.BaseURL),
					AccessToken: bearer,
					BoundJKT:    claims.Confirmation,
				})
				if derr != nil {
					if errors.Is(derr, auth.ErrUseDPoPNonce) {
						// RFC 9449 §9: hand the client a nonce to retry with. Guard
						// the empty case so an RNG failure never advertises an empty
						// DPoP-Nonce (an infinite-retry trap).
						if n := cfg.DPoP.IssueNonce(cfg.Now()); n != "" {
							w.Header().Set("DPoP-Nonce", n)
						}
					}
					cfg.writeAuthError(w, derr)
					return
				}
			}

			if cfg.RateLimiter != nil {
				ok, retryAfter := cfg.RateLimiter.Allow(claims.Subject, cfg.Now())
				if !ok {
					setRetryAfter(w, retryAfter)
					cfg.writeAuthError(w, auth.ErrRateLimitExceeded)
					return
				}
			}

			// RFC 9449 §8.2: rotate a fresh nonce onto the successful response so
			// a client whose nonce is near expiry gets a new one without a 401.
			// IssueNonce returns "" unless a NonceSource is configured, so this is
			// a no-op for non-nonce and non-DPoP setups.
			if cfg.DPoP != nil {
				if n := cfg.DPoP.IssueNonce(cfg.Now()); n != "" {
					w.Header().Set("DPoP-Nonce", n)
					w.Header().Set("Cache-Control", "no-store")
				}
			}

			ctx := auth.WithClaims(r.Context(), claims)
			ctx = auth.WithRawToken(ctx, bearer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractBearer parses the Authorization header and returns the token, or
// auth.ErrMissingToken if the header is absent or malformed.
//
// The header is matched case-insensitively per RFC 7235 §2.1. The token is
// NOT logged or persisted by this function.
func extractBearer(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", auth.ErrMissingToken
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", auth.ErrMissingToken
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", auth.ErrMissingToken
	}
	return token, nil
}

// writeAuthError serializes an *auth.Error to a JSON body with the matching
// status code and an RFC 6750 / RFC 9728 challenge in WWW-Authenticate. Any
// non-*auth.Error is logged and returned as a generic 500 -- so a bug in
// upstream code does NOT accidentally return a 200 with auth bypass.
func (cfg MiddlewareConfig) writeAuthError(w http.ResponseWriter, err error) {
	var e *auth.Error
	if !errors.As(err, &e) {
		cfg.Logger.Error("auth: unclassified error", slog.Any("err", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	cfg.Logger.Info(
		"auth_rejected",
		slog.String("code", e.Code),
		slog.Int("status", e.HTTPStatus),
		slog.Any("cause", e.Cause),
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", buildWWWAuthenticate(e, cfg.ResourceMetadataURL, cfg.Scopes))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.HTTPStatus)

	// Encode without exposing the wrapped cause -- that field is intentionally
	// absent from the JSON tags.
	if encErr := json.NewEncoder(w).Encode(e); encErr != nil {
		cfg.Logger.Warn("auth: write response failed", slog.Any("err", encErr))
	}
}

// buildWWWAuthenticate composes the challenge per RFC 6750 §3, RFC 9449 §7.1,
// and RFC 9728 §5.1. The scheme is Bearer for all errors except
// invalid_dpop_proof, which uses the DPoP scheme (RFC 9449 §7.1). The error
// parameter uses only registered codes. A missing-token 401 and a generic
// forbidden 403 omit the error parameter per RFC 6750. resource_metadata
// points the client at the RFC 9728 metadata document when configured.
func buildWWWAuthenticate(e *auth.Error, resourceMetadataURL string, scopes []string) string {
	scheme := "Bearer"
	params := []string{`realm="mcp"`}

	switch e.Code {
	case auth.ErrInvalidToken.Code:
		params = append(params, `error="invalid_token"`)
	case auth.ErrExpiredToken.Code:
		// Expired maps to the registered invalid_token code; the description
		// preserves the actionable "re-authenticate" signal for clients.
		params = append(params, `error="invalid_token"`, `error_description="the access token expired"`)
	case auth.ErrInsufficientScope.Code:
		params = append(params, `error="insufficient_scope"`)
		if len(scopes) > 0 {
			params = append(params, `scope="`+sanitizeQuoted(strings.Join(scopes, " "))+`"`)
		}
	case auth.ErrInvalidDPoPProof.Code:
		// RFC 9449 §7.1: use the DPoP scheme for DPoP-specific rejections.
		scheme = "DPoP"
		params = append(params, `error="invalid_dpop_proof"`)
	case auth.ErrUseDPoPNonce.Code:
		// RFC 9449 §9: demand a nonce with the DPoP scheme. The DPoP-Nonce header
		// carrying the value is set by the middleware, not here.
		scheme = "DPoP"
		params = append(params, `error="use_dpop_nonce"`)
	}

	if resourceMetadataURL != "" {
		params = append(params, `resource_metadata="`+sanitizeQuoted(resourceMetadataURL)+`"`)
	}

	return scheme + " " + strings.Join(params, ", ")
}

// requestURL derives the htu source for DPoP enforcement. With baseURL set
// (proxied deployments) it uses that public scheme+authority and the request
// path; otherwise it reconstructs from the request (scheme from r.TLS). Query
// and fragment are irrelevant -- dpop.checkProof strips them.
func requestURL(r *http.Request, baseURL string) string {
	if baseURL != "" {
		return strings.TrimRight(baseURL, "/") + r.URL.Path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// sanitizeQuoted strips characters that would break the quoted-string in a
// WWW-Authenticate header per RFC 7230 token grammar. Our error codes are
// already safe, but this is belt-and-braces.
func sanitizeQuoted(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' || c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// setRetryAfter writes the integer-seconds Retry-After header per RFC 9110.
// Sub-second durations round up to 1; zero or negative durations are omitted
// (the header is only meaningful when the client should wait).
func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	if d <= 0 {
		return
	}
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
}
