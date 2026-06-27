package http_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"

	auth "github.com/polyglotdev/mcp-auth-go"
	authhttp "github.com/polyglotdev/mcp-auth-go/transport/http"
)

// ExampleMetadataHandler shows the RFC 9728 Protected Resource Metadata
// document an MCP client fetches to discover the authorization server.
func ExampleMetadataHandler() {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := authhttp.MetadataHandler(logger, authhttp.ProtectedResourceMetadata{
		Resource:               "https://mcp.internal.acme.com",
		AuthorizationServers:   []string{"https://acme.okta.com/oauth2/aus1a2b3c"},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"mcp:read", "mcp:write"},
	})

	req := httptest.NewRequest(http.MethodGet, authhttp.MetadataPath, nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	var meta authhttp.ProtectedResourceMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &meta); err != nil {
		log.Fatal(err)
	}

	fmt.Println("status:", rr.Code)
	fmt.Println("content-type:", rr.Header().Get("Content-Type"))
	fmt.Println("resource:", meta.Resource)

	// Output:
	// status: 200
	// content-type: application/json
	// resource: https://mcp.internal.acme.com
}

// ExampleMiddlewareConfig_Middleware shows the full HTTP wiring: the validating
// middleware in front of a protected handler, plus the metadata endpoint a
// client uses to discover the authorization server.
func ExampleMiddlewareConfig_Middleware() {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:  "https://acme.okta.com/oauth2/aus1a2b3c/v1/keys",
		Issuer:   "https://acme.okta.com/oauth2/aus1a2b3c",
		Audience: "https://mcp.internal.acme.com",
		Verifiers: []auth.ClaimVerifier{
			auth.VerifyRequiredStringClaims(map[string]string{"scope": "mcp:read"}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Handlers behind the middleware read the verified claims from the context.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := auth.MustClaims(r.Context())
		_, _ = fmt.Fprintln(w, "hello", claims.Subject)
	})

	mw := authhttp.MiddlewareConfig{Validator: v, Logger: logger}.Middleware()

	mux := http.NewServeMux()
	mux.Handle("/mcp", mw(protected))
	mux.HandleFunc(authhttp.MetadataPath, authhttp.MetadataHandler(logger, authhttp.ProtectedResourceMetadata{
		Resource:             "https://mcp.internal.acme.com",
		AuthorizationServers: []string{"https://acme.okta.com/oauth2/aus1a2b3c"},
	}))

	_ = mux
}
