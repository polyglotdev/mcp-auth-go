package mcpauth

import (
	"net/http"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
)

// Options configure [RequireBearerToken].
type Options struct {
	// ResourceMetadataURL is echoed in the WWW-Authenticate challenge as the
	// RFC 9728 resource_metadata pointer, so a client can discover this
	// resource's metadata (and its authorization server) from a 401 or 403.
	// Set it to the absolute URL of the
	// /.well-known/oauth-protected-resource document.
	ResourceMetadataURL string

	// Scopes are the scopes every request's token must carry. The SDK enforces
	// them against the validated token's scopes and answers a shortfall with an
	// RFC 6750 insufficient_scope 403 challenge.
	//
	// Prefer enforcing scopes here rather than with auth.RequireScopes on the
	// Validator: this adapter can only surface a Validator-level scope failure
	// as 401 (the SDK's TokenVerifier contract has no 403), whereas Options
	// .Scopes yields a proper 403 + scope challenge.
	Scopes []string

	// DPoP, when set, enforces RFC 9449 proof-of-possession (via the SDK
	// verifier's *http.Request) after a successful Validate. RequireBearerToken
	// then wraps the response so a DPoP failure is answered with a DPoP-schemed
	// WWW-Authenticate challenge (RFC 9449 §7.1) and, when a nonce is configured,
	// a DPoP-Nonce header (§9); a successful response rotates a fresh nonce (§8.2).
	// A bare NewTokenVerifier cannot shape the response, so it yields the SDK's
	// Bearer challenge -- use RequireBearerToken for the DPoP challenge.
	DPoP *dpop.Verifier

	// BaseURL overrides the htu scheme+authority for DPoP enforcement behind a
	// proxy (see transport/http MiddlewareConfig.BaseURL).
	BaseURL string
}

// RequireBearerToken returns middleware that validates the bearer token with v
// and applies the MCP Go SDK's bearer-token enforcement: 401 on a missing or
// invalid token, 403 on insufficient scope. When opts.DPoP is set, RFC 9449
// proof-of-possession is enforced after a successful Validate. opts may be nil.
func RequireBearerToken(v auth.TokenValidator, opts *Options) func(http.Handler) http.Handler {
	var sdkOpts *sdkauth.RequireBearerTokenOptions
	var dv *dpop.Verifier
	baseURL := ""
	resourceMetadataURL := ""
	if opts != nil {
		sdkOpts = &sdkauth.RequireBearerTokenOptions{
			ResourceMetadataURL: opts.ResourceMetadataURL,
			Scopes:              opts.Scopes,
		}
		dv = opts.DPoP
		baseURL = opts.BaseURL
		resourceMetadataURL = opts.ResourceMetadataURL
	}
	inner := sdkauth.RequireBearerToken(newVerifierFunc(v, dv, baseURL), sdkOpts)
	if dv == nil {
		return inner // no DPoP: plain SDK middleware, no wrapper
	}
	return dpopChallengeMiddleware(inner, dv, resourceMetadataURL)
}
