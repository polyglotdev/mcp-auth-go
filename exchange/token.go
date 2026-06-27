package exchange

import "time"

// Token is the result of a successful exchange. AccessToken is a secret.
type Token struct {
	AccessToken     string
	IssuedTokenType string    // RFC 8693 issued_token_type URN
	TokenType       string    // "Bearer" or "DPoP", verbatim from the AS
	ExpiresAt       time.Time // derived from response expires_in; zero if absent
	Scopes          []string
}
