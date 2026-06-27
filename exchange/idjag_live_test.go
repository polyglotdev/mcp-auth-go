package exchange_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/polyglotdev/mcp-auth-go/exchange"
)

// TestOktaLiveIDJAG attempts the two-step Identity Assertion JWT Authorization
// Grant (Cross App Access) flow against a real Okta org and LOGS whether the org
// supports it -- whether the id-jag grant profile is advertised in authorization
// server metadata and whether the token endpoint honors
// requested_token_type=urn:ietf:params:oauth:token-type:id-jag.
//
// Cross App Access is newer than the RFC 8693 exchange already proven by
// TestOktaLiveExchange; whether the dev org supports it is the one fact only the
// network can confirm. If the org does not support id-jag, the test SKIPs with a
// logged reason (the unit tests fully cover the wire behavior).
//
// The test is skipped unless OKTA_ISSUER, OKTA_CLIENT_ID, and OKTA_CLIENT_SECRET
// are set. The subject token defaults to a client_credentials token (which an
// id-jag-enabled org will reject, since id-jag wants a user identity assertion);
// supply OKTA_IDJAG_SUBJECT_TOKEN (a real ID Token) and OKTA_IDJAG_RESOURCE_AS
// (the Resource AS issuer) to exercise the full flow. Inject secrets at runtime:
//
//	OKTA_ISSUER="https://trial-1352610.okta.com/oauth2/default" \
//	OKTA_CLIENT_ID="$(op read 'op://HealthBridge/Okta MCP dev/client_id')" \
//	OKTA_CLIENT_SECRET="$(op read 'op://HealthBridge/Okta MCP dev/client_secret')" \
//	go test -run TestOktaLiveIDJAG -count=1 -v ./exchange/
func TestOktaLiveIDJAG(t *testing.T) {
	issuer := os.Getenv("OKTA_ISSUER")
	clientID := os.Getenv("OKTA_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_CLIENT_SECRET")
	if issuer == "" || clientID == "" || clientSecret == "" {
		t.Skip("set OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET to run the live Okta ID-JAG test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	idpTokenURL := issuer + "/v1/token"

	// Log whether the IdP authorization-server metadata advertises the id-jag
	// grant profile. Best-effort: a non-advertising org may still honor it.
	logGrantProfiles(ctx, t, issuer)

	// The subject token: a caller-supplied ID Token if available, else a
	// client_credentials token (which an id-jag org will reject -- still useful
	// to log how the endpoint responds to the id-jag requested_token_type).
	subjectToken := os.Getenv("OKTA_IDJAG_SUBJECT_TOKEN")
	subjectTokenType := exchange.TokenTypeIDToken
	if subjectToken == "" {
		scope := os.Getenv("OKTA_EXCHANGE_SCOPE")
		if scope == "" {
			scope = "mcp:read"
		}
		subjectToken = liveExchangeFetchToken(ctx, t, idpTokenURL, clientID, clientSecret, scope)
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
		t.Log("no OKTA_IDJAG_SUBJECT_TOKEN: using a client_credentials access token as the subject (an id-jag org will likely reject it)")
	}

	resourceASIssuer := os.Getenv("OKTA_IDJAG_RESOURCE_AS")
	if resourceASIssuer == "" {
		resourceASIssuer = issuer // self as Resource AS for the probe
	}

	// Step 1: attempt to mint an ID-JAG via RFC 8693 token exchange at the IdP.
	idpEx, err := exchange.NewExchanger(exchange.Config{
		TokenURL:   idpTokenURL,
		ClientAuth: mustDPoP(t, exchange.BasicAuth{ClientID: clientID, ClientSecret: clientSecret}),
	})
	if err != nil {
		t.Fatalf("NewExchanger (IdP): %v", err)
	}
	idjag, err := idpEx.Exchange(ctx, exchange.Request{
		SubjectToken:       subjectToken,
		SubjectTokenType:   subjectTokenType,
		RequestedTokenType: exchange.TokenTypeIDJAG,
		Audience:           resourceASIssuer,
	})
	if err != nil {
		t.Skipf("Okta org does not support the id-jag exchange (expected if Cross App Access is not enabled): %v", err)
	}
	if idjag.IssuedTokenType != exchange.TokenTypeIDJAG {
		t.Logf("step 1 returned issued_token_type=%q (want %q)", idjag.IssuedTokenType, exchange.TokenTypeIDJAG)
	}
	t.Logf("step 1 OK: minted an ID-JAG (issued_token_type=%s, expires=%s)", idjag.IssuedTokenType, idjag.ExpiresAt)

	// Step 2: redeem the ID-JAG for a downstream access token at the Resource AS.
	resourceASTokenURL := os.Getenv("OKTA_IDJAG_RESOURCE_AS_TOKEN_URL")
	if resourceASTokenURL == "" {
		resourceASTokenURL = resourceASIssuer + "/v1/token"
	}
	rasEx, err := exchange.NewExchanger(exchange.Config{
		TokenURL:   resourceASTokenURL,
		ClientAuth: exchange.BasicAuth{ClientID: clientID, ClientSecret: clientSecret},
	})
	if err != nil {
		t.Fatalf("NewExchanger (Resource AS): %v", err)
	}
	tok, err := rasEx.RedeemAssertion(ctx, idjag.AccessToken)
	if err != nil {
		t.Skipf("step 2 jwt-bearer redemption not supported by the Resource AS: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("step 2 returned an empty access token")
	}
	t.Logf("step 2 OK: downstream token_type=%s scopes=%v expires=%s", tok.TokenType, tok.Scopes, tok.ExpiresAt)
}

// logGrantProfiles fetches the issuer's OAuth authorization-server metadata and
// logs whether it advertises the id-jag grant profile. Best-effort; never fails
// the test.
func logGrantProfiles(ctx context.Context, t *testing.T, issuer string) {
	t.Helper()
	metaURL := strings.TrimSuffix(issuer, "/") + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		t.Logf("grant-profile probe: build request: %v", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Logf("grant-profile probe: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var meta struct {
		AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Logf("grant-profile probe: decode metadata (%d): %v", resp.StatusCode, err)
		return
	}
	const profile = "urn:ietf:params:oauth:grant-profile:id-jag"
	supported := false
	for _, p := range meta.AuthorizationGrantProfilesSupported {
		if p == profile {
			supported = true
		}
	}
	t.Logf("AS metadata authorization_grant_profiles_supported=%v (advertises id-jag: %v)", meta.AuthorizationGrantProfilesSupported, supported)
}
