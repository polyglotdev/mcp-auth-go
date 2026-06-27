package auth

import (
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Claims is the library's typed view of a validated JWT. It hides jwx's
// generic Token interface from downstream code so handlers and audit logging
// can depend on auth without importing jwx.
type Claims struct {
	// Subject is the Okta sub claim -- a stable, opaque user identifier.
	// This is the right key for rate limiting and session tracking. NEVER
	// log Email or other PII; sub is the PHI-safe identifier.
	Subject string

	// Email is the user's email (if the issuer included the email claim). May
	// be empty. Treated as PII -- only use it for audit logs that go to
	// BAA-covered storage, never as a telemetry/OTel attribute.
	Email string

	// Issuer is the verified iss claim. Useful for multi-tenant gateways and
	// auditability.
	Issuer string

	// Audience is the verified aud claim list.
	Audience []string

	// ExpiresAt is when the token becomes invalid.
	ExpiresAt time.Time

	// IssuedAt is when the issuer minted the token. Used to detect replay
	// attempts (an auditor can warn if token age exceeds an expected max).
	IssuedAt time.Time

	// Scopes are the OAuth scopes granted to the token.
	Scopes []string

	// Confirmation is the cnf.jkt confirmation thumbprint (the RFC 7638 JWK
	// SHA-256 Thumbprint, base64url) binding this token to a DPoP key, or ""
	// if the token is not DPoP-bound. The validator extracts it; the dpop
	// package enforces possession (RFC 9449 resource-server side).
	Confirmation string

	// Raw is a passthrough of any additional string claims an auditor or
	// downstream handler might need. Populated with the string-typed private
	// claims the issuer sent, except the ones already extracted above (email,
	// scope, scp). Authorization-policy claims (for example a backend or tier
	// claim) appear here -- the core does not special-case any product claim.
	Raw map[string]string
}

// claimsFromToken builds the typed Claims from a jwx token. Only scalar string
// claims propagate to Raw -- arrays / nested objects are dropped because they
// don't have a stable, audit-safe representation here.
func claimsFromToken(tok jwt.Token) *Claims {
	c := &Claims{
		Subject:   tok.Subject(),
		Issuer:    tok.Issuer(),
		Audience:  tok.Audience(),
		ExpiresAt: tok.Expiration(),
		IssuedAt:  tok.IssuedAt(),
		Raw:       map[string]string{},
	}

	if v, ok := tok.Get("email"); ok {
		if s, ok := v.(string); ok {
			c.Email = s
		}
	}
	c.Scopes = scopesFromToken(tok)

	// cnf.jkt binds the token to a DPoP key (RFC 9449 §6). It is a nested
	// object, so it never lands in Raw (the loop below only copies string
	// claims); pull the jkt thumbprint out explicitly for the dpop
	// resource-server check.
	if cnf, ok := tok.Get("cnf"); ok {
		if m, ok := cnf.(map[string]any); ok {
			if jkt, ok := m["jkt"].(string); ok {
				c.Confirmation = jkt
			}
		}
	}

	// Capture remaining string-typed private claims for audit propagation.
	// PrivateClaims returns map[string]any of non-registered claims. email and
	// the scope claims are skipped because they're already extracted above.
	for k, v := range tok.PrivateClaims() {
		if k == "email" || k == "scope" || k == "scp" {
			continue
		}
		if s, ok := v.(string); ok {
			c.Raw[k] = s
		}
	}
	return c
}

// scopesFromToken normalizes Okta's scope representation. Okta emits scopes
// either as a single space-delimited "scope" string OR as an array under
// "scp" (depending on auth-server config). We accept both.
func scopesFromToken(tok jwt.Token) []string {
	if v, ok := tok.Get("scp"); ok {
		if arr, ok := v.([]any); ok {
			out := make([]string, 0, len(arr))
			for _, x := range arr {
				if s, ok := x.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
	}
	if v, ok := tok.Get("scope"); ok {
		if s, ok := v.(string); ok {
			return splitScopes(s)
		}
	}
	return nil
}

// splitScopes splits an Okta `scope` claim on whitespace, dropping empties.
// Avoids strings.Fields' cost for the common single-scope case.
func splitScopes(s string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	return out
}
