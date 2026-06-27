package introspection_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/polyglotdev/mcp-auth-go/introspection"
)

// TestOktaLiveIntrospection introspects a real token against an Okta
// authorization server's RFC 7662 endpoint using introspection.Validator.
//
// It is skipped unless OKTA_ISSUER, OKTA_CLIENT_ID, and OKTA_CLIENT_SECRET are
// set, so an ordinary `go test` run without credentials never reaches the
// network. The token to introspect is either supplied via OKTA_INTROSPECT_TOKEN
// (mint it however the org requires) or minted here via client_credentials with
// client_secret_basic (no DPoP, so this file stays jwx-free).
//
// It first performs a RAW introspection and logs which RFC 7662 members Okta
// returns -- this is the one fact the design's fail-closed posture deliberately
// verifies live rather than asserting from memory (whether Okta's default
// authorization server returns iss/aud). It then runs the Validator end-to-end.
//
// Inject secrets at runtime (never commit credentials):
//
//	OKTA_ISSUER="https://trial-1352610.okta.com/oauth2/default" \
//	OKTA_CLIENT_ID="$(op read 'op://HealthBridge/Okta MCP dev/client_id')" \
//	OKTA_CLIENT_SECRET="$(op read 'op://HealthBridge/Okta MCP dev/client_secret')" \
//	OKTA_INTROSPECT_SCOPE="mcp:read" \
//	go test -run TestOktaLiveIntrospection -count=1 -v ./introspection/
func TestOktaLiveIntrospection(t *testing.T) {
	issuer := os.Getenv("OKTA_ISSUER")
	clientID := os.Getenv("OKTA_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_CLIENT_SECRET")
	if issuer == "" || clientID == "" || clientSecret == "" {
		t.Skip("set OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET to run the live Okta introspection test")
	}
	introspectURL := issuer + "/v1/introspect"
	scope := envOr("OKTA_INTROSPECT_SCOPE", "mcp:read")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token := os.Getenv("OKTA_INTROSPECT_TOKEN")
	if token == "" {
		token = liveMintClientCredentials(ctx, t, issuer+"/v1/token", clientID, clientSecret, scope)
	}

	raw := liveRawIntrospect(ctx, t, introspectURL, clientID, clientSecret, token)
	if active, _ := raw["active"].(bool); !active {
		t.Fatalf("introspection returned active=false for a fresh token; response members=%v", sortedKeys(raw))
	}
	t.Logf("Okta introspection response members present: iss=%t aud=%t sub=%t scope=%t exp=%t token_type=%t (all keys: %v)",
		has(raw, "iss"), has(raw, "aud"), has(raw, "sub"), has(raw, "scope"), has(raw, "exp"), has(raw, "token_type"), sortedKeys(raw))

	issResp, _ := raw["iss"].(string)
	if issResp == "" {
		t.Skipf("Okta introspection response has no iss; the Validator requires it. Configure the AS to return iss. members=%v", sortedKeys(raw))
	}
	audResp := firstAudience(raw["aud"])
	if audResp == "" {
		t.Skipf("Okta introspection response has no aud; the Validator requires it for audience isolation. members=%v", sortedKeys(raw))
	}

	v, err := introspection.NewValidator(introspection.Config{
		IntrospectionURL: introspectURL,
		ClientAuth:       introspection.BasicAuth{ClientID: clientID, ClientSecret: clientSecret},
		Issuer:           issResp,
		Audience:         audResp,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	claims, err := v.Validate(ctx, token)
	if err != nil {
		t.Fatalf("live introspection validate failed: %v", err)
	}
	// Log metadata only -- never the token.
	t.Logf("live introspection OK: subject=%s issuer=%s audience=%v scopes=%v",
		claims.Subject, claims.Issuer, claims.Audience, claims.Scopes)
}

// liveMintClientCredentials mints an access token via the OAuth
// client_credentials grant with client_secret_basic (no DPoP). If the org
// requires DPoP, supply OKTA_INTROSPECT_TOKEN instead.
func liveMintClientCredentials(ctx context.Context, t *testing.T, tokenURL, clientID, clientSecret, scope string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		t.Fatalf("token endpoint returned %d: %s (%s) -- if the org requires DPoP, set OKTA_INTROSPECT_TOKEN",
			resp.StatusCode, body.Error, body.ErrorDescription)
	}
	return body.AccessToken
}

// liveRawIntrospect performs a raw RFC 7662 introspection and returns the
// decoded JSON object, so the test can observe which members Okta returns.
func liveRawIntrospect(ctx context.Context, t *testing.T, introspectURL, clientID, clientSecret, token string) map[string]any {
	t.Helper()
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build introspection request: %v", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspection request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspection endpoint returned %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode introspection response: %v", err)
	}
	return m
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func has(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func firstAudience(v any) string {
	switch a := v.(type) {
	case string:
		return a
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
