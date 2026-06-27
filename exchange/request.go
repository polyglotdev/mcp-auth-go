package exchange

// Request is one token exchange. SubjectToken is required; everything else is
// optional. Subject is the caller identity used ONLY for the per-caller cache
// key -- supply it explicitly (the sub claim); it is never derived from
// SubjectToken, and an empty Subject means this exchange is not cached.
type Request struct {
	SubjectToken string   // REQUIRED -- the caller's inbound access token
	Subject      string   // optional -- cache-key identity (sub); empty => uncached
	Audience     string   // optional -- RFC 8693 audience
	Resource     string   // optional -- RFC 8693 resource (URI)
	Scope        []string // optional -- requested downstream scopes
	ActorToken   string   // optional -- RFC 8693 actor_token (delegation)

	// SubjectTokenType is the RFC 8693 subject_token_type. Optional; defaults to
	// urn:ietf:params:oauth:token-type:access_token (delegation/impersonation).
	// Set TokenTypeIDToken / TokenTypeSAML2 / TokenTypeRefreshToken (with
	// RequestedTokenType = TokenTypeIDJAG) to mint an Identity Assertion JWT
	// Authorization Grant.
	SubjectTokenType string
	// RequestedTokenType is the RFC 8693 requested_token_type. Optional; the
	// default is omitted, so the authorization server returns its default access
	// token. Set TokenTypeIDJAG to request an ID-JAG.
	RequestedTokenType string
}
