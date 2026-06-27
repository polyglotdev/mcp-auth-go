package exchange_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/polyglotdev/mcp-auth-go/exchange"
)

// TestOktaLiveExchange mints a real subject token from an Okta authorization
// server (client_credentials + DPoP, mirroring the root okta_live_test.go
// pattern) and then exchanges it for a downstream token using exchange.Exchanger.
//
// The test is skipped unless OKTA_ISSUER, OKTA_CLIENT_ID, and
// OKTA_CLIENT_SECRET are set, so an ordinary `go test` run without credentials
// never reaches the network.
//
// Inject secrets at runtime (never commit credentials):
//
//	OKTA_ISSUER="https://trial-1352610.okta.com/oauth2/default" \
//	OKTA_CLIENT_ID="$(op read 'op://HealthBridge/Okta MCP dev/client_id')" \
//	OKTA_CLIENT_SECRET="$(op read 'op://HealthBridge/Okta MCP dev/client_secret')" \
//	OKTA_EXCHANGE_AUDIENCE="api://default" OKTA_EXCHANGE_SCOPE="mcp:read" \
//	go test -run TestOktaLiveExchange -count=1 -v ./exchange/
func TestOktaLiveExchange(t *testing.T) {
	issuer := os.Getenv("OKTA_ISSUER")
	clientID := os.Getenv("OKTA_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_CLIENT_SECRET")
	if issuer == "" || clientID == "" || clientSecret == "" {
		t.Skip("set OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET to run the live Okta exchange test")
	}

	audience := os.Getenv("OKTA_EXCHANGE_AUDIENCE")
	if audience == "" {
		audience = "api://default"
	}
	scope := os.Getenv("OKTA_EXCHANGE_SCOPE")
	if scope == "" {
		scope = "mcp:read"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenURL := issuer + "/v1/token"

	// Mint a real subject token using the same DPoP client-credentials pattern
	// as the root okta_live_test.go (lines ~90-203).
	subjectToken := liveExchangeFetchToken(ctx, t, tokenURL, clientID, clientSecret, scope)

	// Build an Exchanger with DPoP wrapping BasicAuth — the same credentials
	// the subject token was minted with act as the MCP server's client auth.
	ex, err := exchange.NewExchanger(exchange.Config{
		TokenURL:   tokenURL,
		ClientAuth: mustDPoP(t, exchange.BasicAuth{ClientID: clientID, ClientSecret: clientSecret}),
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}

	tok, err := ex.Exchange(ctx, exchange.Request{
		SubjectToken: subjectToken,
		Subject:      "live-client",
		Audience:     audience,
		Scope:        []string{scope},
	})
	if err != nil {
		t.Fatalf("live exchange failed: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("live exchange returned an empty token")
	}
	// Log metadata only -- never log the token itself.
	t.Logf("live exchange OK: token_type=%s scopes=%v expires=%s", tok.TokenType, tok.Scopes, tok.ExpiresAt)
}

// mustDPoP wraps exchange.NewDPoP, failing the test on error.
func mustDPoP(t *testing.T, base exchange.ClientAuthenticator) *exchange.DPoP {
	t.Helper()
	d, err := exchange.NewDPoP(base)
	if err != nil {
		t.Fatalf("NewDPoP: %v", err)
	}
	return d
}

// liveExchangeFetchToken performs the OAuth client_credentials grant with an
// RFC 9449 DPoP proof and returns the access token. It mirrors
// fetchOktaToken in the root okta_live_test.go (lines ~90-141). On a
// use_dpop_nonce challenge it retries once with the server-supplied nonce.
func liveExchangeFetchToken(ctx context.Context, t *testing.T, tokenURL, clientID, clientSecret, scope string) string {
	t.Helper()
	key := liveExchangeNewDPoPKey(t)

	var nonce string
	for attempt := 0; attempt < 2; attempt++ {
		proof := liveExchangeDPoPProof(t, key, http.MethodPost, tokenURL, nonce)

		form := url.Values{
			"grant_type": {"client_credentials"},
			"scope":      {scope},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("build token request: %v", err)
		}
		req.SetBasicAuth(clientID, clientSecret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("DPoP", proof)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token request: %v", err)
		}

		var body struct {
			AccessToken      string `json:"access_token"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&body)
		serverNonce := resp.Header.Get("DPoP-Nonce")
		status := resp.StatusCode
		_ = resp.Body.Close()
		if decErr != nil {
			t.Fatalf("decode token response: %v", decErr)
		}
		if status == http.StatusOK && body.AccessToken != "" {
			return body.AccessToken
		}
		if body.Error == "use_dpop_nonce" && serverNonce != "" && attempt == 0 {
			nonce = serverNonce
			continue
		}
		t.Fatalf("token endpoint %s returned %d: %s (%s)", tokenURL, status, body.Error, body.ErrorDescription)
	}
	t.Fatal("dpop token exchange did not return a token")
	return ""
}

func liveExchangeNewDPoPKey(t *testing.T) jwk.Key {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}
	key, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk from raw: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		t.Fatalf("set dpop alg: %v", err)
	}
	return key
}

func liveExchangeDPoPProof(t *testing.T, key jwk.Key, htm, htu, nonce string) string {
	t.Helper()
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatalf("dpop public key: %v", err)
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		t.Fatalf("dpop jti: %v", err)
	}
	claims := map[string]any{
		"htm": htm,
		"htu": htu,
		"jti": hex.EncodeToString(jti),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal dpop claims: %v", err)
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.TypeKey, "dpop+jwt"); err != nil {
		t.Fatalf("set dpop typ: %v", err)
	}
	if err := hdr.Set(jws.JWKKey, pub); err != nil {
		t.Fatalf("set dpop jwk: %v", err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	return string(signed)
}
