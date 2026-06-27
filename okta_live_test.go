package auth_test

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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// TestOktaLiveValidation mints a real access token from an Okta custom
// authorization server (the client-credentials grant, with an RFC 9449 DPoP
// proof) and validates it end-to-end with the library. It is skipped unless
// OKTA_ISSUER, OKTA_CLIENT_ID, and OKTA_CLIENT_SECRET are set, so an ordinary
// `go test` or CI run without credentials never reaches the network.
//
// Inject the secrets from 1Password at runtime, with no file on disk — e.g.:
//
//	OKTA_ISSUER="https://YOUR-ORG.okta.com/oauth2/default" \
//	OKTA_CLIENT_ID="$(op read 'op://<vault>/<item>/client_id')" \
//	OKTA_CLIENT_SECRET="$(op read 'op://<vault>/<item>/client_secret')" \
//	go test -run TestOktaLiveValidation -v .
//
// The 1Password item can be named anything; only the op:// path must match it.
// Optional: OKTA_AUDIENCE (default "api://default") and OKTA_SCOPE (default
// "mcp:read").
func TestOktaLiveValidation(t *testing.T) {
	issuer := os.Getenv("OKTA_ISSUER")
	clientID := os.Getenv("OKTA_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_CLIENT_SECRET")
	if issuer == "" || clientID == "" || clientSecret == "" {
		t.Skip("set OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET (e.g. via `op run`) to run the live Okta check")
	}

	audience := os.Getenv("OKTA_AUDIENCE")
	if audience == "" {
		audience = "api://default"
	}
	scope := os.Getenv("OKTA_SCOPE")
	if scope == "" {
		scope = "mcp:read"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token := fetchOktaToken(ctx, t, issuer+"/v1/token", clientID, clientSecret, scope)

	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:  issuer + "/v1/keys",
		Issuer:   issuer,
		Audience: audience,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	claims, err := v.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate rejected a real Okta token: %v", err)
	}

	t.Logf("validated real Okta token: sub=%q iss=%q aud=%v scopes=%v",
		claims.Subject, claims.Issuer, claims.Audience, claims.Scopes)
	if claims.Issuer != issuer {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, issuer)
	}
	if !slices.Contains(claims.Scopes, scope) {
		t.Errorf("Scopes = %v, want to contain %q", claims.Scopes, scope)
	}
}

// fetchOktaToken performs the OAuth client-credentials grant with an RFC 9449
// DPoP proof and returns the access token. If the server demands a nonce
// (use_dpop_nonce), it retries once with the supplied DPoP-Nonce.
func fetchOktaToken(ctx context.Context, t *testing.T, tokenURL, clientID, clientSecret, scope string) string {
	t.Helper()
	key := newDPoPKey(t)

	var nonce string
	for attempt := 0; attempt < 2; attempt++ {
		proof := dpopProof(t, key, http.MethodPost, tokenURL, nonce)

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
		// Okta may require a server-supplied nonce: retry once with it.
		if body.Error == "use_dpop_nonce" && serverNonce != "" && attempt == 0 {
			nonce = serverNonce
			continue
		}
		t.Fatalf("token endpoint %s returned %d: %s (%s)", tokenURL, status, body.Error, body.ErrorDescription)
	}
	t.Fatal("dpop token exchange did not return a token")
	return ""
}

// newDPoPKey generates an ephemeral EC P-256 key for one DPoP exchange.
func newDPoPKey(t *testing.T) jwk.Key {
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

// dpopProof builds and signs an RFC 9449 DPoP proof JWT binding the request
// (htm/htu) to key, embedding the public key in the header and an optional
// server-supplied nonce.
func dpopProof(t *testing.T, key jwk.Key, htm, htu, nonce string) string {
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
