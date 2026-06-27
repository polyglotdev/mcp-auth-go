package mcpauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
)

// NewTokenVerifier adapts a Validator into the MCP Go SDK's
// [sdkauth.TokenVerifier], so it can be passed to
// [sdkauth.RequireBearerToken]. On success the validated claims are mapped
// into an [sdkauth.TokenInfo]; on failure the error is returned for the SDK to
// turn into an HTTP response. For DPoP enforcement, use [RequireBearerToken]
// with [Options.DPoP].
func NewTokenVerifier(v auth.TokenValidator) sdkauth.TokenVerifier {
	return newVerifierFunc(v, nil, "")
}

// newVerifierFunc builds the SDK TokenVerifier closure. When dv is non-nil it
// enforces RFC 9449 proof-of-possession using the request's DPoP header and
// the validated claims' confirmation thumbprint. It fails closed if dv is set
// and the SDK provides no request.
func newVerifierFunc(v auth.TokenValidator, dv *dpop.Verifier, baseURL string) sdkauth.TokenVerifier {
	if v == nil {
		panic("mcpauth: a non-nil auth.TokenValidator is required") // construction-time guard; not a request handler
	}
	return func(ctx context.Context, token string, req *http.Request) (*sdkauth.TokenInfo, error) {
		claims, err := v.Validate(ctx, token)
		if err != nil {
			return nil, toVerifierError(err)
		}
		if dv != nil {
			if req == nil {
				// The SDK normally provides a request; fail closed if it does not.
				return nil, toVerifierError(auth.ErrInvalidDPoPProof.With(errors.New("no request available for dpop check")))
			}
			derr := dv.Enforce(ctx, dpop.Input{
				Proofs:      req.Header.Values("DPoP"),
				Method:      req.Method,
				URL:         requestURL(req, baseURL),
				AccessToken: token,
				BoundJKT:    claims.Confirmation,
			})
			if derr != nil {
				// Record the DPoP failure so the response wrapper (when installed by
				// RequireBearerToken) can emit a DPoP-scheme challenge. Best-effort:
				// no-op if no holder is on the context (e.g. NewTokenVerifier path).
				if st, ok := ctx.Value(challengeKey{}).(*challengeState); ok {
					st.isDPoP = true
					if errors.Is(derr, auth.ErrUseDPoPNonce) {
						st.code = auth.ErrUseDPoPNonce.Code
					} else {
						st.code = auth.ErrInvalidDPoPProof.Code
					}
				}
				return nil, toVerifierError(derr)
			}
		}
		ti := toTokenInfo(claims)
		ti.Extra[rawTokenExtraKey] = token
		return ti, nil
	}
}

// requestURL mirrors transport/http: the public htu source for the DPoP proof
// check. With baseURL set (proxied deployments) it uses that public
// scheme+authority and the request path; otherwise it reconstructs from the
// request (scheme inferred from r.TLS).
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

// verifierError carries a safe, public message while unwrapping to the SDK's
// [sdkauth.ErrInvalidToken] sentinel. RequireBearerToken classifies it by that
// sentinel (so the response is 401, never a 500) and writes Error() verbatim as
// the body -- so Error() must expose only the public message, never the
// validator's wrapped cause.
type verifierError struct {
	msg string
}

func (e *verifierError) Error() string { return e.msg }

func (e *verifierError) Unwrap() error { return sdkauth.ErrInvalidToken }

// toVerifierError maps any Validate failure onto the only verifier-level
// rejection the SDK's TokenVerifier contract supports: an error unwrapping to
// ErrInvalidToken (HTTP 401). Authentication failures (bad signature, wrong
// audience, expired) and authorization failures (a ClaimVerifier returning
// ErrForbidden or ErrInsufficientScope) both surface as 401, because the SDK
// gives a TokenVerifier no way to signal 403 -- that path exists only for the
// SDK's own scope check against RequireBearerTokenOptions.Scopes. Enforce
// required scopes there (see [Options]) to get an RFC 6750 insufficient_scope
// 403 challenge.
//
// Only the *auth.Error public Message is exposed; the wrapped Cause is dropped
// so validator internals never reach the response body.
func toVerifierError(err error) error {
	var ae *auth.Error
	if errors.As(err, &ae) {
		return &verifierError{msg: ae.Message}
	}
	return &verifierError{msg: sdkauth.ErrInvalidToken.Error()}
}

// claimsExtraKey is the TokenInfo.Extra key under which NewTokenVerifier stashes
// the validated *auth.Claims, so ClaimsFromContext can recover the full typed
// claims at the MCP layer. It is namespaced so it cannot collide with a token
// claim copied from Claims.Raw.
const claimsExtraKey = "github.com/polyglotdev/mcp-auth-go.claims"

// rawTokenExtraKey is the TokenInfo.Extra key under which NewTokenVerifier
// stashes the caller's raw bearer token, so RawTokenFromContext can recover it
// for RFC 8693 token exchange. Namespaced to avoid collision with Claims.Raw.
const rawTokenExtraKey = "github.com/polyglotdev/mcp-auth-go.raw_token" //nolint:gosec // G101 false positive: this is a context map key, not a credential

// toTokenInfo maps the library's typed Claims onto the SDK's TokenInfo. The SDK
// uses UserID to bind the session to a single caller, Expiration to re-check
// token freshness, and Scopes for its own authorization check. The full typed
// Claims are stashed in Extra (the SDK's verifier-to-handler channel) so
// ClaimsFromContext can recover them for per-tool gating.
func toTokenInfo(c *auth.Claims) *sdkauth.TokenInfo {
	extra := make(map[string]any, len(c.Raw)+1)
	for k, v := range c.Raw {
		extra[k] = v
	}
	extra[claimsExtraKey] = c
	return &sdkauth.TokenInfo{
		Scopes:     c.Scopes,
		Expiration: c.ExpiresAt,
		UserID:     c.Subject,
		Extra:      extra,
	}
}

// ClaimsFromContext returns the validated [auth.Claims] for this request, or
// (nil, false) if the request was not authenticated. Use it from per-tool gates
// (see [ToolGate]) and from tool handlers to read the authenticated caller.
//
// It first honors claims placed under the core's context key by
// [auth.WithClaims] (used by in-memory transports and tests), then falls back to
// the claims [NewTokenVerifier] stashed in the SDK's TokenInfo for the bearer
// HTTP path.
func ClaimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	if c, ok := auth.ClaimsFrom(ctx); ok {
		return c, true
	}
	if ti := sdkauth.TokenInfoFromContext(ctx); ti != nil {
		if c, ok := ti.Extra[claimsExtraKey].(*auth.Claims); ok {
			return c, true
		}
	}
	return nil, false
}

// RawTokenFromContext returns the caller's raw bearer token for this request, or
// ("", false) if unauthenticated. It honors the core key set by
// auth.WithRawToken first, then falls back to the value NewTokenVerifier stashed
// in the SDK's TokenInfo. The token is a secret -- never log it.
func RawTokenFromContext(ctx context.Context) (string, bool) {
	if raw, ok := auth.RawTokenFrom(ctx); ok {
		return raw, true
	}
	if ti := sdkauth.TokenInfoFromContext(ctx); ti != nil {
		if raw, ok := ti.Extra[rawTokenExtraKey].(string); ok {
			return raw, true
		}
	}
	return "", false
}
