package auth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
)

// TestValidatorRejectsNoneAlg proves an unsigned ("alg":"none") token — the
// classic signature-stripping attack — is rejected even when its claims are
// otherwise valid. A validator backed by a key set must never accept an
// unsigned token.
func TestValidatorRejectsNoneAlg(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":"alice","exp":%d}`,
		j.Issuer(), j.Audience(), time.Now().Add(time.Hour).Unix())
	payload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	token := header + "." + payload + "." // empty signature segment

	if _, err := v.Validate(context.Background(), token); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken (alg=none must be rejected)", err)
	}
}

// TestValidatorRejectsHMACConfusion proves an HS256 token is rejected by a
// validator whose JWKS holds RS256 keys — the RS256→HS256 algorithm-confusion
// attack, where an attacker signs with HMAC using the public key as the shared
// secret. The validator must only honor the algorithms in its key set.
func TestValidatorRejectsHMACConfusion(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	tok, err := jwt.NewBuilder().
		Issuer(j.Issuer()).
		Audience([]string{j.Audience()}).
		Subject("alice").
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, []byte("attacker-chosen-secret")))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.Validate(context.Background(), string(signed)); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken (HMAC confusion must be rejected)", err)
	}
}

// FuzzValidate proves Validate never panics and always returns exactly one of
// (claims, nil) or (nil, error) for arbitrary bearer input. The seed corpus
// runs during a normal `go test`; drive the full fuzzer with:
//
//	go test -run x -fuzz FuzzValidate
func FuzzValidate(f *testing.F) {
	j := jwkstest.New(f)
	v := newValidator(f, j)

	f.Add("")
	f.Add("not-a-jwt")
	f.Add("a.b.c")
	f.Add("Bearer x")
	f.Add(j.Mint(f, jwkstest.ClaimSet{
		Subject: "alice",
		Private: map[string]any{requiredClaim: requiredValue},
	}))

	f.Fuzz(func(t *testing.T, bearer string) {
		claims, err := v.Validate(context.Background(), bearer)
		if (claims == nil) == (err == nil) {
			t.Errorf("Validate(%q): exactly one of claims/err must be non-nil (claims=%v err=%v)", bearer, claims, err)
		}
	})
}
