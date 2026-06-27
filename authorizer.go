package auth

import (
	"context"
	"errors"
	"fmt"
)

// Authorizer is a post-validation authorization policy over typed [Claims]. It
// is the composable counterpart to [ClaimVerifier]: where a ClaimVerifier runs
// at validation time against the raw jwx token, an Authorizer runs anywhere a
// *Claims is in hand -- in particular at an MCP per-tool gate, after the bearer
// token has already been validated.
//
// An Authorizer returns nil to allow and a non-nil error to deny -- by
// convention [ErrForbidden] or [ErrInsufficientScope], so a transport maps the
// denial to the right response. The context is the caller's request context, so
// an Authorizer may perform context-aware checks and observe cancellation.
//
// Compose policies with [AllOf] and [AnyOf]; build leaves with [HasScopes],
// [HasAnyScope], and [HasClaim].
type Authorizer func(ctx context.Context, c *Claims) error

// HasScopes returns an Authorizer that requires the caller to hold every scope
// in required. A missing scope yields [ErrInsufficientScope]. When required is
// empty the Authorizer is a no-op (always allows).
func HasScopes(required ...string) Authorizer {
	return func(_ context.Context, c *Claims) error {
		if len(required) == 0 {
			return nil
		}
		have := make(map[string]struct{}, len(c.Scopes))
		for _, s := range c.Scopes {
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

// HasAnyScope returns an Authorizer that requires the caller to hold at least
// one of scopes. A caller holding none yields [ErrInsufficientScope]. When
// scopes is empty the Authorizer is a no-op (always allows).
func HasAnyScope(scopes ...string) Authorizer {
	return func(_ context.Context, c *Claims) error {
		if len(scopes) == 0 {
			return nil
		}
		have := make(map[string]struct{}, len(c.Scopes))
		for _, s := range c.Scopes {
			have[s] = struct{}{}
		}
		for _, want := range scopes {
			if _, ok := have[want]; ok {
				return nil
			}
		}
		return ErrInsufficientScope.With(fmt.Errorf("none of the scopes %v present", scopes))
	}
}

// HasClaim returns an Authorizer that requires the private string claim name to
// equal value. A missing or non-matching claim yields [ErrForbidden]. Only the
// private string claims captured in [Claims.Raw] are matched; registered claims
// (sub, iss) have typed fields and are not checked here.
func HasClaim(name, value string) Authorizer {
	return func(_ context.Context, c *Claims) error {
		if got, ok := c.Raw[name]; !ok || got != value {
			return ErrForbidden.With(fmt.Errorf("claim %q != %q", name, value))
		}
		return nil
	}
}

// AllOf returns an Authorizer that allows only when every authorizer allows. It
// runs them in order and returns the first denial unchanged, so the specific
// reason and its HTTP status survive. AllOf with no authorizers allows.
func AllOf(authorizers ...Authorizer) Authorizer {
	return func(ctx context.Context, c *Claims) error {
		for _, a := range authorizers {
			if err := a(ctx, c); err != nil {
				return err
			}
		}
		return nil
	}
}

// AnyOf returns an Authorizer that allows when any authorizer allows, running
// them in order and short-circuiting on the first to allow. If none allow -- or
// the set is empty -- it denies with [ErrForbidden].
func AnyOf(authorizers ...Authorizer) Authorizer {
	return func(ctx context.Context, c *Claims) error {
		for _, a := range authorizers {
			if a(ctx, c) == nil {
				return nil
			}
		}
		return ErrForbidden.With(errors.New("no authorizer allowed the request"))
	}
}

// AllowAll is an Authorizer that always allows. Use it as a readable no-op, or
// as a gate default to make unlisted tools callable.
func AllowAll(context.Context, *Claims) error { return nil }

// DenyAll is an Authorizer that always denies with [ErrForbidden]. Use it as a
// gate default to fail closed -- every tool must then be explicitly allowed.
func DenyAll(context.Context, *Claims) error { return ErrForbidden }
