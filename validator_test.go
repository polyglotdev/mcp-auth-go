package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
)

// The validator is configured with a generic required-claim verifier so the
// tests exercise verifier injection rather than any product-specific policy.
const (
	requiredClaim = "tier"
	requiredValue = "internal"
)

// newValidator wires up a Validator pointed at the test JWKS, enforcing the
// requiredClaim via an injected VerifyRequiredStringClaims verifier.
func newValidator(t testing.TB, j *jwkstest.JWKS) *auth.Validator {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:            j.URL(),
		Issuer:             j.Issuer(),
		Audience:           j.Audience(),
		MinRefreshInterval: time.Minute,
		ClockSkew:          5 * time.Second,
		Verifiers: []auth.ClaimVerifier{
			auth.VerifyRequiredStringClaims(map[string]string{requiredClaim: requiredValue}),
		},
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// TestValidatorHappyPath proves a well-formed token with the required claim
// round-trips through Validate and surfaces typed Claims (Subject, Email,
// Scopes), with the required claim visible in Raw (it is no longer a
// dedicated struct field).
func TestValidatorHappyPath(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice@hb.com",
		Email:   "alice@hb.com",
		Private: map[string]any{
			requiredClaim: requiredValue,
			"scope":       "mcp:read mcp:write",
		},
	})

	claims, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "alice@hb.com" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Email != "alice@hb.com" {
		t.Errorf("Email = %q", claims.Email)
	}
	if claims.Raw[requiredClaim] != requiredValue {
		t.Errorf("Raw[%q] = %q, want %q", requiredClaim, claims.Raw[requiredClaim], requiredValue)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "mcp:read" || claims.Scopes[1] != "mcp:write" {
		t.Errorf("Scopes = %v", claims.Scopes)
	}
}

// TestValidatorRejectsMissingRequiredClaim proves a token correct in every
// other way but lacking the required claim is rejected with ErrForbidden
// (HTTP 403) by the injected verifier.
func TestValidatorRejectsMissingRequiredClaim(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	token := j.Mint(t, jwkstest.ClaimSet{Subject: "alice@hb.com"}) // no tier claim

	_, err := v.Validate(context.Background(), token)
	assertForbidden(t, err)
}

// TestValidatorRejectsWrongRequiredClaim exercises every shape of "claim
// present but not the value we require". Each must surface as ErrForbidden.
func TestValidatorRejectsWrongRequiredClaim(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "different string", value: "external"},
		{name: "case-sensitive mismatch", value: "INTERNAL"},
		{name: "empty string", value: ""},
		{name: "wrong type int", value: 123},
		{name: "wrong type bool", value: true},
	}

	j := jwkstest.New(t)
	v := newValidator(t, j)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := j.Mint(t, jwkstest.ClaimSet{
				Subject: "alice@hb.com",
				Private: map[string]any{requiredClaim: tc.value},
			})
			_, err := v.Validate(context.Background(), token)
			assertForbidden(t, err)
		})
	}
}

// TestValidatorRejectsExpiredToken proves an expired token is rejected with
// ErrExpiredToken (the actionable "please re-auth" 401 variant) rather than a
// generic ErrInvalidToken. Expiry is caught at parse, before verifiers run.
func TestValidatorRejectsExpiredToken(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject:  "alice",
		NotAfter: -time.Hour, // already expired
		Private:  map[string]any{requiredClaim: requiredValue},
	})

	_, err := v.Validate(context.Background(), token)
	if !errors.Is(err, auth.ErrExpiredToken) {
		t.Errorf("err = %v, want ErrExpiredToken", err)
	}
}

// TestValidatorRejectsWrongAudience confirms the audience claim is enforced.
func TestValidatorRejectsWrongAudience(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject:  "alice",
		Audience: "https://wrong.audience.example.com",
		Private:  map[string]any{requiredClaim: requiredValue},
	})

	_, err := v.Validate(context.Background(), token)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

// TestValidatorRejectsWrongIssuer confirms the issuer claim is enforced.
func TestValidatorRejectsWrongIssuer(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Issuer:  "https://impostor.example.com",
		Private: map[string]any{requiredClaim: requiredValue},
	})

	_, err := v.Validate(context.Background(), token)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

// TestValidatorRejectsBadSignature signs a token with an unrelated key and
// confirms it is rejected. This proves the JWKS lookup actually gates
// signature acceptance.
func TestValidatorRejectsBadSignature(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	token := j.MintWithWrongKey(t, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{requiredClaim: requiredValue},
	})

	_, err := v.Validate(context.Background(), token)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

// TestValidatorRejectsEmptyBearer proves the validator surfaces ErrMissingToken
// when handed an empty string -- the transport should not need to pre-check
// for emptiness.
func TestValidatorRejectsEmptyBearer(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	_, err := v.Validate(context.Background(), "")
	if !errors.Is(err, auth.ErrMissingToken) {
		t.Errorf("err = %v, want ErrMissingToken", err)
	}
}

// TestValidatorRejectsGarbageToken feeds non-JWT input shapes through Validate
// and confirms each surfaces as ErrInvalidToken (or ErrExpiredToken in the
// malformed-claim case) instead of crashing.
func TestValidatorRejectsGarbageToken(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "not a jwt at all", input: "not-a-jwt"},
		{name: "malformed three segments", input: "a.b.c"},
		{name: "kilobyte of x", input: strings.Repeat("x", 1024)},
	}

	j := jwkstest.New(t)
	v := newValidator(t, j)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), tc.input)
			if !errors.Is(err, auth.ErrInvalidToken) && !errors.Is(err, auth.ErrExpiredToken) {
				t.Errorf("input %q: err = %v, want ErrInvalidToken", tc.input, err)
			}
		})
	}
}

// TestNewValidatorRejectsBadConfig proves NewValidator fails fast on configs
// missing any of the three required URLs / values, so a misconfigured
// deployment errors at startup, not on first request.
func TestNewValidatorRejectsBadConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  auth.ValidatorConfig
	}{
		{name: "missing jwks url", cfg: auth.ValidatorConfig{Issuer: "x", Audience: "y"}},
		{name: "missing issuer", cfg: auth.ValidatorConfig{JWKSURL: "http://x", Audience: "y"}},
		{name: "missing audience", cfg: auth.ValidatorConfig{JWKSURL: "http://x", Issuer: "y"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := auth.NewValidator(context.Background(), tc.cfg)
			if err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}
