package auth

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ClaimVerifier runs an authorization policy check against a token whose
// signature and standard claims (iss, aud, exp, nbf) have already been
// verified. The validator runs each configured verifier in order after a
// successful parse and returns the first non-nil error unchanged.
//
// A verifier that rejects a token should return an authorization failure --
// typically ErrForbidden (wrapped with the reason via With) -- so transport
// adapters map it to 403 rather than 401. Returning a non-*Error value is
// allowed but will be surfaced as a generic 500 by HTTP transports, so
// verifiers should prefer ErrForbidden.With(reason).
//
// The context is the request context, so verifiers may perform context-aware
// checks (for example a remote policy lookup) and observe cancellation.
type ClaimVerifier func(ctx context.Context, tok jwt.Token) error

// VerifyRequiredStringClaims returns a ClaimVerifier that requires every
// claim in required to be present, string-typed, and equal to the expected
// value. It is the generic replacement for hard-coded claim enforcement: a
// caller that needs, say, claude_backend=bedrock passes that pair here
// instead of the library knowing the claim.
//
// Any missing claim, non-string claim, or value mismatch yields ErrForbidden
// (HTTP 403) with the offending claim wrapped as the cause for logs. The
// public Message is never rewritten, so the reason is not leaked to clients.
//
// When required is empty the verifier is a no-op. Claims are checked in
// unspecified (map) order; when multiple claims fail, which one is reported
// in the cause is not deterministic, but the outcome (ErrForbidden) is.
func VerifyRequiredStringClaims(required map[string]string) ClaimVerifier {
	return func(_ context.Context, tok jwt.Token) error {
		for name, want := range required {
			raw, ok := tok.Get(name)
			if !ok {
				return ErrForbidden.With(fmt.Errorf("claim %q missing", name))
			}
			got, ok := raw.(string)
			if !ok || got != want {
				return ErrForbidden.With(fmt.Errorf("claim %q != %q", name, want))
			}
		}
		return nil
	}
}

// RequireScopes returns a ClaimVerifier that requires the token to carry every
// scope in required. Okta emits scopes either as a space-delimited "scope"
// string or as an array "scp" claim; both are accepted.
//
// A token missing any required scope yields ErrInsufficientScope (HTTP 403) so
// an HTTP transport can surface an RFC 6750 insufficient_scope challenge and
// the client can request step-up authorization. When required is empty the
// verifier is a no-op.
func RequireScopes(required ...string) ClaimVerifier {
	return func(_ context.Context, tok jwt.Token) error {
		if len(required) == 0 {
			return nil
		}
		have := make(map[string]struct{}, len(required))
		for _, s := range scopesFromToken(tok) {
			have[s] = struct{}{}
		}
		for _, want := range required {
			if _, ok := have[want]; !ok {
				return ErrInsufficientScope.With(fmt.Errorf("missing scope %q", want))
			}
		}
		return nil
	}
}
