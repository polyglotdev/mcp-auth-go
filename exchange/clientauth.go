package exchange

import (
	"net/http"
	"net/url"
)

// ClientAuthenticator decorates the outgoing token-exchange request to
// authenticate the MCP server to the AS. form is the already-encoded body (for
// schemes that sign over request parameters). nonce is empty on the first
// attempt and, on a use_dpop_nonce challenge, the server-supplied DPoP-Nonce on
// the single retry; schemes that don't use it ignore it.
type ClientAuthenticator interface {
	Apply(req *http.Request, form url.Values, nonce string) error
}

// BasicAuth authenticates with HTTP Basic (client_secret_basic). It ignores the
// nonce.
type BasicAuth struct {
	ClientID     string
	ClientSecret string
}

// Apply sets HTTP Basic authentication on req.
func (b BasicAuth) Apply(req *http.Request, _ url.Values, _ string) error {
	req.SetBasicAuth(b.ClientID, b.ClientSecret)
	return nil
}
