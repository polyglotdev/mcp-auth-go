package mcpauth_test

import (
	"context"
	"log"
	"net/http"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/transport/mcpauth"
)

// ExampleRequireBearerToken shows the recommended one-call wiring: validate the
// bearer token (including the RFC 8707 audience check) in front of an official
// MCP Go SDK server handler, requiring a scope and advertising the RFC 9728
// metadata document on a 401/403 challenge.
func ExampleRequireBearerToken() {
	ctx := context.Background()

	// The validator owns the JWKS cache; the initial fetch is synchronous so a
	// misconfigured issuer fails fast at startup.
	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:  "https://acme.okta.com/oauth2/aus1a2b3c/v1/keys",
		Issuer:   "https://acme.okta.com/oauth2/aus1a2b3c",
		Audience: "https://mcp.internal.acme.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	// The MCP server handler from the official SDK.
	server := mcp.NewServer(&mcp.Implementation{Name: "acme-mcp", Version: "1.0.0"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)

	// Secure it. Required scopes go here (not on the Validator) so an insufficient
	// scope yields the SDK's RFC 6750 insufficient_scope 403 challenge.
	secured := mcpauth.RequireBearerToken(v, &mcpauth.Options{
		ResourceMetadataURL: "https://mcp.internal.acme.com/.well-known/oauth-protected-resource",
		Scopes:              []string{"mcp:read"},
	})(handler)

	mux := http.NewServeMux()
	mux.Handle("/mcp", secured)
	_ = mux
}

// ExampleNewTokenVerifier shows the lower-level primitive: NewTokenVerifier
// returns an [sdkauth.TokenVerifier], so it composes with the SDK's
// RequireBearerToken directly when you'd rather wire the middleware yourself.
func ExampleNewTokenVerifier() {
	ctx := context.Background()

	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:  "https://acme.okta.com/oauth2/aus1a2b3c/v1/keys",
		Issuer:   "https://acme.okta.com/oauth2/aus1a2b3c",
		Audience: "https://mcp.internal.acme.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	verifier := mcpauth.NewTokenVerifier(v)
	secured := sdkauth.RequireBearerToken(verifier, &sdkauth.RequireBearerTokenOptions{
		Scopes: []string{"mcp:read"},
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp", secured(http.NotFoundHandler()))
	_ = mux
}

// ExampleToolGate shows per-tool authorization: a sensitive tool is gated behind
// a scope-and-role policy at the MCP method layer, while the bearer middleware
// authenticates every request in front of it.
func ExampleToolGate() {
	ctx := context.Background()
	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:  "https://acme.okta.com/oauth2/aus1a2b3c/v1/keys",
		Issuer:   "https://acme.okta.com/oauth2/aus1a2b3c",
		Audience: "https://mcp.internal.acme.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "acme-mcp", Version: "1.0.0"}, nil)
	// ... register tools with mcp.AddTool(server, ...) ...

	// Gate the write tool: callers need mcp:write and a clinician role. Tools
	// absent from Policies require only a valid token; set Default: auth.DenyAll
	// to fail closed instead.
	server.AddReceivingMiddleware(mcpauth.ToolGate{
		Policies: map[string]auth.Authorizer{
			"write_prescription": auth.AllOf(
				auth.HasScopes("mcp:write"),
				auth.HasClaim("role", "clinician"),
			),
		},
	}.Middleware())

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	secured := mcpauth.RequireBearerToken(v, nil)(handler)

	mux := http.NewServeMux()
	mux.Handle("/mcp", secured)
	_ = mux
}
