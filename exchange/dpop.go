package exchange

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// DPoP decorates a base ClientAuthenticator with an RFC 9449 proof. It holds
// one long-lived ES256 key for its lifetime (stable jkt) -- the proof
// construction mirrors okta_live_test.go but the key is long-lived, not
// per-call. The private key is process-memory-only: never logged, serialized,
// or exported.
type DPoP struct {
	base ClientAuthenticator
	key  jwk.Key
}

// NewDPoP generates an ES256 key pair and returns a *DPoP wrapping base.
// base may be nil for proof-only use, but most authorization servers also
// require client authentication (e.g. BasicAuth).
func NewDPoP(base ClientAuthenticator) (*DPoP, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	key, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, err
	}
	return &DPoP{base: base, key: key}, nil
}

// Apply calls the base ClientAuthenticator (if set) and then sets the DPoP
// header on req. nonce is included in the proof when non-empty (used on the
// one-shot use_dpop_nonce retry in Exchanger.do).
func (d *DPoP) Apply(req *http.Request, form url.Values, nonce string) error {
	if d.base != nil {
		if err := d.base.Apply(req, form, nonce); err != nil {
			return err
		}
	}
	proof, err := d.proof(req.Method, req.URL.String(), nonce)
	if err != nil {
		return err
	}
	req.Header.Set("DPoP", proof)
	return nil
}

// proof builds and signs an RFC 9449 DPoP proof JWT for the given HTTP method
// and URL, optionally including a server-supplied nonce.
func (d *DPoP) proof(htm, htu, nonce string) (string, error) {
	pub, err := d.key.PublicKey()
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
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
		return "", err
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.TypeKey, "dpop+jwt"); err != nil {
		return "", err
	}
	if err := hdr.Set(jws.JWKKey, pub); err != nil {
		return "", err
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, d.key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}
