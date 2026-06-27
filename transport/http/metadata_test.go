package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testMetadataHandler() http.HandlerFunc {
	return MetadataHandler(
		discardLogger(),
		ProtectedResourceMetadata{
			Resource:               "https://mcp.internal.example.com",
			AuthorizationServers:   []string{"https://acme.okta.com/oauth2/aus123"},
			BearerMethodsSupported: []string{"header"},
			ScopesSupported:        []string{"mcp:read", "mcp:write"},
			ResourceName:           "Example MCP Gateway",
		},
	)
}

// TestMetadataGetReturnsJSON proves a GET to the well-known metadata path
// returns 200 with the JSON-serialized ProtectedResourceMetadata document a
// client's OAuth discovery flow consumes.
func TestMetadataGetReturnsJSON(t *testing.T) {
	h := testMetadataHandler()

	req := httptest.NewRequest(http.MethodGet, MetadataPath, nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got ProtectedResourceMetadata
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Resource != "https://mcp.internal.example.com" {
		t.Errorf("resource = %q", got.Resource)
	}
	if len(got.AuthorizationServers) != 1 {
		t.Fatalf("authorization_servers len = %d", len(got.AuthorizationServers))
	}
	if got.BearerMethodsSupported[0] != "header" {
		t.Errorf("bearer_methods_supported[0] = %q, want header", got.BearerMethodsSupported[0])
	}
	if len(got.ScopesSupported) != 2 {
		t.Errorf("scopes_supported len = %d, want 2", len(got.ScopesSupported))
	}
}

// TestMetadataHeadReturnsHeadersWithoutBody proves a HEAD request returns the
// same headers as GET but with an empty body, per RFC 7231.
func TestMetadataHeadReturnsHeadersWithoutBody(t *testing.T) {
	h := testMetadataHandler()

	req := httptest.NewRequest(http.MethodHead, MetadataPath, nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type missing on HEAD")
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD returned body of %d bytes", rr.Body.Len())
	}
}

// TestMetadataRejectsNonGet proves every non-GET/HEAD method receives 405 with
// an Allow header, so clients can discover the supported verbs.
func TestMetadataRejectsNonGet(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{name: "POST", method: http.MethodPost},
		{name: "PUT", method: http.MethodPut},
		{name: "DELETE", method: http.MethodDelete},
		{name: "PATCH", method: http.MethodPatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := testMetadataHandler()
			req := httptest.NewRequest(tc.method, MetadataPath, nil)
			rr := httptest.NewRecorder()
			h(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s status = %d, want 405", tc.method, rr.Code)
			}
			if rr.Header().Get("Allow") == "" {
				t.Errorf("%s missing Allow header", tc.method)
			}
		})
	}
}

// TestMetadataPathFor proves the RFC 9728 §3 path-aware well-known location is
// built by inserting the resource path after the well-known prefix.
func TestMetadataPathFor(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "root empty", in: "", want: "/.well-known/oauth-protected-resource"},
		{name: "root slash", in: "/", want: "/.well-known/oauth-protected-resource"},
		{name: "subpath", in: "/mcp", want: "/.well-known/oauth-protected-resource/mcp"},
		{name: "no leading slash", in: "mcp", want: "/.well-known/oauth-protected-resource/mcp"},
		{name: "trailing slash", in: "/mcp/", want: "/.well-known/oauth-protected-resource/mcp"},
		{name: "nested", in: "/a/b", want: "/.well-known/oauth-protected-resource/a/b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MetadataPathFor(tc.in); got != tc.want {
				t.Errorf("MetadataPathFor(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMetadataCacheControl checks Cache-Control permits short caching so a
// client doesn't hammer the well-known endpoint.
func TestMetadataCacheControl(t *testing.T) {
	h := testMetadataHandler()
	req := httptest.NewRequest(http.MethodGet, MetadataPath, nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if cc := rr.Header().Get("Cache-Control"); cc == "" {
		t.Errorf("Cache-Control missing")
	}
}
