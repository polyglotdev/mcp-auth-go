// Package http adapts the transport-agnostic auth package to net/http: a
// validating middleware and an RFC 9728 Protected Resource Metadata handler.
//
// It depends on the root auth package; the root package never depends on this
// one. Consumers typically import it under an alias, e.g.
//
//	import authhttp "github.com/polyglotdev/mcp-auth-go/transport/http"
package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// MetadataPath is the RFC 9728 well-known location for OAuth Protected
// Resource Metadata. A client discovers the authorization server by GETting
// this path on the MCP server.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc9728
const MetadataPath = "/.well-known/oauth-protected-resource"

// MetadataPathFor returns the RFC 9728 §3 path-aware well-known location for a
// resource served under resourcePath. An MCP server mounted at a sub-path
// (e.g. "/mcp") serves its metadata at the inserted location
// "/.well-known/oauth-protected-resource/mcp", not at the root MetadataPath.
//
// A resourcePath of "" or "/" returns the root MetadataPath.
func MetadataPathFor(resourcePath string) string {
	resourcePath = strings.Trim(resourcePath, "/")
	if resourcePath == "" {
		return MetadataPath
	}
	return MetadataPath + "/" + resourcePath
}

// ProtectedResourceMetadata is the JSON document served at MetadataPath.
//
// Fields are named per RFC 9728 §2. Omitted fields (resource_signing_alg_*,
// resource_documentation, jwks_uri, etc.) are not required for a basic
// deployment and can be added later without breaking existing clients.
type ProtectedResourceMetadata struct {
	// Resource is the canonical URL of this MCP server, used by clients to
	// verify the audience claim of their token. It MUST match the JWT `aud`.
	Resource string `json:"resource"`

	// AuthorizationServers is the list of OAuth 2.1 issuer URLs this resource
	// server accepts tokens from (without the /.well-known/... suffix).
	AuthorizationServers []string `json:"authorization_servers"`

	// BearerMethodsSupported documents how the token is presented. We accept
	// only Authorization: Bearer headers (not query params or POST body).
	BearerMethodsSupported []string `json:"bearer_methods_supported"`

	// ScopesSupported lists the OAuth scopes valid against this resource. A
	// client requests these during the authorization-code flow.
	ScopesSupported []string `json:"scopes_supported"`

	// ResourceName is a human-readable label for the protected resource,
	// shown to the user in the issuer's consent dialog.
	ResourceName string `json:"resource_name,omitempty"`
}

// MetadataHandler returns an http.HandlerFunc serving the RFC 9728 document
// derived from meta. Only GET and HEAD are allowed; everything else returns
// 405 with an Allow header.
//
// The document is precomputed at startup so the handler is allocation-free on
// the hot path -- the well-known endpoint is hit on every cold connection
// from a new client.
func MetadataHandler(logger *slog.Logger, meta ProtectedResourceMetadata) http.HandlerFunc {
	body, err := json.Marshal(meta)
	if err != nil {
		// Marshalling a struct of strings/string-slices cannot fail in
		// practice. Panic at construction so a misconfigured deployment fails
		// loudly rather than at request time.
		panic("auth/http: marshal metadata: " + err.Error()) // construction-time; static struct marshal cannot fail
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		if _, err := w.Write(body); err != nil {
			logger.Warn("metadata: write failed", slog.Any("err", err))
		}
	}
}
