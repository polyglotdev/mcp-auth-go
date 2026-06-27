package introspection

import (
	"net/http"
	"net/url"
)

// ClientAuthenticator decorates the outgoing introspection request to
// authenticate the resource server to the authorization server. RFC 7662
// section 4 requires the introspection endpoint to be protected, so a
// ClientAuthenticator is mandatory (Config.ClientAuth) -- without it the
// endpoint would be a token-scanning oracle.
//
// Apply may set request headers and/or mutate form. The validator calls Apply
// BEFORE encoding the request body from form, so a body-mutating scheme (such as
// FormPost) lands in the wire body. ClientID/ClientSecret are credentials and
// are never logged or surfaced in an error.
type ClientAuthenticator interface {
	Apply(req *http.Request, form url.Values) error
}

// BasicAuth authenticates with HTTP Basic (RFC 7662 client_secret_basic). It
// sets the Authorization header and does not touch the body.
type BasicAuth struct {
	ClientID     string
	ClientSecret string
}

// Apply sets HTTP Basic authentication on req.
func (b BasicAuth) Apply(req *http.Request, _ url.Values) error {
	req.SetBasicAuth(b.ClientID, b.ClientSecret)
	return nil
}

// FormPost authenticates by placing the client credentials in the request body
// (RFC 7662 client_secret_post). It mutates form; the validator encodes the body
// after Apply so the added parameters are sent.
type FormPost struct {
	ClientID     string
	ClientSecret string
}

// Apply adds client_id and client_secret to form.
func (f FormPost) Apply(_ *http.Request, form url.Values) error {
	form.Set("client_id", f.ClientID)
	form.Set("client_secret", f.ClientSecret)
	return nil
}
