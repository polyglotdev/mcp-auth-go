package exchange_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/polyglotdev/mcp-auth-go/exchange"
)

func TestBasicAuthSetsHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://as/token", nil)
	if err := (exchange.BasicAuth{ClientID: "id", ClientSecret: "sec"}).Apply(req, nil, ""); err != nil {
		t.Fatal(err)
	}
	u, p, ok := req.BasicAuth()
	if !ok || u != "id" || p != "sec" {
		t.Fatalf("basic auth = %q/%q/%v", u, p, ok)
	}
}
