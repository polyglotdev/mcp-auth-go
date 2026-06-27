package dpop_test

// TestOktaLiveDPoP mints a real DPoP-bound access token from an Okta
// authorization server using the client-credentials grant, validates it with
// auth.Validator (proving auth.Claims.Confirmation is populated from a real
// cnf.jkt), builds a matching resource-server presentation proof, and asserts
// Enforce accepts it. A tampered variant (wrong ath) is asserted rejected.
//
// Skipped unless OKTA_ISSUER, OKTA_CLIENT_ID, and OKTA_CLIENT_SECRET are set
// in the environment. Inject secrets from 1Password at runtime, e.g.:
//
//	OKTA_ISSUER="https://trial-1352610.okta.com/oauth2/default" \
//	OKTA_CLIENT_ID="$(op read 'op://HealthBridge/Okta MCP dev/client_id')" \
//	OKTA_CLIENT_SECRET="$(op read 'op://HealthBridge/Okta MCP dev/client_secret')" \
//	go test -run TestOktaLiveDPoP -count=1 -v ./dpop/

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
)

func TestOktaLiveDPoP(t *testing.T) {
	issuer := os.Getenv("OKTA_ISSUER")
	clientID := os.Getenv("OKTA_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_CLIENT_SECRET")
	if issuer == "" || clientID == "" || clientSecret == "" {
		t.Skip("set OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET to run the live DPoP RS check")
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

	// Generate a test-held ES256 key to use for both the token-request DPoP
	// proof and the resource-server presentation proof.
	key := liveNewKey(t)

	// Fetch a real DPoP-bound access token using the test key.
	tokenURL := issuer + "/v1/token"
	accessToken := liveFetchToken(ctx, t, key, tokenURL, clientID, clientSecret, scope)

	// Validate the token: Claims.Confirmation must be non-empty (Okta's real
	// cnf.jkt, proving Task 1 works against a live token).
	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:  issuer + "/v1/keys",
		Issuer:   issuer,
		Audience: audience,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	claims, err := v.Validate(ctx, accessToken)
	if err != nil {
		t.Fatalf("Validate rejected a real DPoP-bound Okta token: %v", err)
	}
	if claims.Confirmation == "" {
		t.Fatal("Claims.Confirmation is empty; expected Okta's cnf.jkt in the token")
	}
	t.Logf("Okta token validated: sub=%q Confirmation=%q", claims.Subject, claims.Confirmation)

	// Build a resource-server DPoP proof bound to a synthetic request.
	const rsMethod = "POST"
	const rsURL = "https://mcp.example/tools/call"
	rsProof := liveBuildRSProof(t, key, rsMethod, rsURL, accessToken)

	dv := dpop.NewVerifier(dpop.Config{
		// Use a generous leeway so the test is not sensitive to clock skew.
		IATLeeway:   120 * time.Second,
		ReplayCache: dpop.NewNopReplayCache(),
	})
	in := dpop.Input{
		Proofs:      []string{rsProof},
		Method:      rsMethod,
		URL:         rsURL,
		AccessToken: accessToken,
		BoundJKT:    claims.Confirmation,
	}

	// Happy path: valid proof accepted.
	if err := dv.Enforce(ctx, in); err != nil {
		t.Fatalf("Enforce rejected a valid RS proof: %v", err)
	}

	// Tampered: wrong ath (hash of a different token) → rejected.
	tamperedProof := liveBuildRSProofWithAth(t, key, rsMethod, rsURL, liveAth("wrong-token"))
	inTampered := dpop.Input{
		Proofs:      []string{tamperedProof},
		Method:      rsMethod,
		URL:         rsURL,
		AccessToken: accessToken,
		BoundJKT:    claims.Confirmation,
	}
	if err := dv.Enforce(ctx, inTampered); !errors.Is(err, auth.ErrInvalidDPoPProof) {
		t.Fatalf("tampered ath: want ErrInvalidDPoPProof, got %v", err)
	}
}

// liveNewKey generates an ephemeral EC P-256 key for one DPoP exchange.
func liveNewKey(t *testing.T) jwk.Key {
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

// liveFetchToken performs the OAuth client-credentials grant with a DPoP proof
// and returns the access token. Retries once with a server-supplied nonce if
// Okta responds with use_dpop_nonce.
func liveFetchToken(ctx context.Context, t *testing.T, key jwk.Key, tokenURL, clientID, clientSecret, scope string) string {
	t.Helper()

	var nonce string
	for attempt := 0; attempt < 2; attempt++ {
		proof := liveTokenProof(t, key, tokenURL, nonce)

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

// liveTokenProof builds a DPoP proof for the token endpoint (AS-side, no ath).
func liveTokenProof(t *testing.T, key jwk.Key, tokenURL, nonce string) string {
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
		"htm": http.MethodPost,
		"htu": tokenURL,
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
		t.Fatalf("sign dpop token proof: %v", err)
	}
	return string(signed)
}

// liveBuildRSProof builds a resource-server DPoP proof (includes ath) for the
// given method/url, bound to the presented access token.
func liveBuildRSProof(t *testing.T, key jwk.Key, method, htu, accessToken string) string {
	t.Helper()
	return liveBuildRSProofWithAth(t, key, method, htu, liveAth(accessToken))
}

// liveBuildRSProofWithAth builds a resource-server DPoP proof with the given
// ath value, so the caller can inject a wrong ath for negative tests.
func liveBuildRSProofWithAth(t *testing.T, key jwk.Key, method, htu, ath string) string {
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
		"htm": method,
		"htu": htu,
		"jti": hex.EncodeToString(jti),
		"iat": time.Now().Unix(),
		"ath": ath,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal dpop rs proof claims: %v", err)
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
		t.Fatalf("sign dpop rs proof: %v", err)
	}
	return string(signed)
}

// liveAth returns the base64url-no-pad SHA-256 of the access token (RFC 9449
// §4.2). The input is a bearer token — never log it.
func liveAth(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
