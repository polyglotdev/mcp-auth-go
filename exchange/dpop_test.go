package exchange_test

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/polyglotdev/mcp-auth-go/exchange"
)

func TestDPoPProofShapeAndChaining(t *testing.T) {
	d, err := exchange.NewDPoP(exchange.BasicAuth{ClientID: "id", ClientSecret: "sec"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "https://as.example/oauth2/default/v1/token", nil)
	if err := d.Apply(req, url.Values{}, ""); err != nil {
		t.Fatal(err)
	}
	// The base BasicAuth must have been chained.
	if _, _, ok := req.BasicAuth(); !ok {
		t.Fatal("DPoP must chain to the base (Basic) auth")
	}
	proof := req.Header.Get("DPoP")
	if proof == "" {
		t.Fatal("missing DPoP header")
	}
	msg, err := jws.Parse([]byte(proof))
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()

	// typ must be "dpop+jwt".
	typ, ok := hdr.Get(jws.TypeKey)
	if !ok || typ != "dpop+jwt" {
		t.Fatalf("typ = %v (ok=%v); want dpop+jwt", typ, ok)
	}
	// The public JWK must be embedded in the header.
	_, ok = hdr.Get(jws.JWKKey)
	if !ok {
		t.Fatal("proof must embed the public JWK in the header")
	}

	// htm/htu must bind the request.
	var claims map[string]any
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if claims["htm"] != "POST" || claims["htu"] != "https://as.example/oauth2/default/v1/token" {
		t.Fatalf("htm/htu = %v / %v", claims["htm"], claims["htu"])
	}
	// jti and iat must be present.
	if _, ok := claims["jti"]; !ok {
		t.Fatal("proof must include jti")
	}
	if _, ok := claims["iat"]; !ok {
		t.Fatal("proof must include iat")
	}
	// nonce must be absent when not supplied.
	if _, ok := claims["nonce"]; ok {
		t.Fatal("nonce must be absent when not supplied")
	}
}

func TestDPoPProofIncludesNonce(t *testing.T) {
	d, err := exchange.NewDPoP(nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "https://as.example/token", nil)
	if err := d.Apply(req, url.Values{}, "server-nonce-1"); err != nil {
		t.Fatal(err)
	}
	proof := req.Header.Get("DPoP")
	msg, err := jws.Parse([]byte(proof))
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if claims["nonce"] != "server-nonce-1" {
		t.Fatalf("nonce = %v; want server-nonce-1", claims["nonce"])
	}
}

func TestDPoPNilBaseDoesNotPanic(t *testing.T) {
	d, err := exchange.NewDPoP(nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "https://as.example/token", nil)
	if err := d.Apply(req, url.Values{}, ""); err != nil {
		t.Fatalf("Apply with nil base: %v", err)
	}
	if req.Header.Get("DPoP") == "" {
		t.Fatal("DPoP header must be set even with nil base")
	}
}
