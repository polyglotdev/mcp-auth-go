package auth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// Example shows the end-to-end shape: construct a Validator against your Okta
// authorization server, inject an authorization policy, and validate a bearer
// token. (Wiring the validator into HTTP is shown in the transport/http
// package.)
func Example() {
	ctx := context.Background()

	// The initial JWKS fetch is synchronous, so a misconfigured issuer fails
	// fast here rather than on the first request.
	v, err := auth.NewValidator(ctx, auth.ValidatorConfig{
		JWKSURL:  "https://acme.okta.com/oauth2/aus1a2b3c/v1/keys",
		Issuer:   "https://acme.okta.com/oauth2/aus1a2b3c",
		Audience: "https://mcp.internal.acme.com",
		// Authorization policy is injected, not built in.
		Verifiers: []auth.ClaimVerifier{
			auth.VerifyRequiredStringClaims(map[string]string{"scope": "mcp:read"}),
		},
	})
	if err != nil {
		log.Fatalf("auth: init: %v", err)
	}

	// bearer is the token from an incoming request's Authorization header.
	var bearer string
	claims, err := v.Validate(ctx, bearer)
	if err != nil {
		// err is an *auth.Error; classify it with errors.Is to pick a status.
		log.Fatalf("auth: reject: %v", err)
	}

	fmt.Println("authenticated:", claims.Subject)
}

// ExampleVerifyRequiredStringClaims shows the built-in authorization policy:
// require a claim to be present and equal to a value. A mismatch is an
// authorization failure ([auth.ErrForbidden], HTTP 403), not authentication.
func ExampleVerifyRequiredStringClaims() {
	verify := auth.VerifyRequiredStringClaims(map[string]string{"mcp_tier": "internal"})

	// Build two unsigned tokens to illustrate; in production the validator
	// hands the already-verified token to the verifier for you.
	internalTok, _ := jwt.NewBuilder().Claim("mcp_tier", "internal").Build()
	externalTok, _ := jwt.NewBuilder().Claim("mcp_tier", "external").Build()

	fmt.Println("internal allowed:", verify(context.Background(), internalTok) == nil)

	if err := verify(context.Background(), externalTok); errors.Is(err, auth.ErrForbidden) {
		fmt.Println("external rejected: forbidden")
	}

	// Output:
	// internal allowed: true
	// external rejected: forbidden
}

// ExampleError shows how a transport classifies a validation failure: branch
// with errors.Is and read HTTPStatus, never the wrapped cause (which may name
// the failing claim and is for logs only).
func ExampleError() {
	// A verifier rejected a valid token; Validate returns ErrForbidden wrapped
	// with the reason.
	err := auth.ErrForbidden.With(errors.New(`claim "mcp_tier" missing`))

	var e *auth.Error
	if errors.As(err, &e) {
		fmt.Printf("%s -> HTTP %d\n", e.Code, e.HTTPStatus)
	}
	fmt.Println("forbidden:", errors.Is(err, auth.ErrForbidden))
	fmt.Println("auth failure:", errors.Is(err, auth.ErrInvalidToken))

	// Output:
	// forbidden -> HTTP 403
	// forbidden: true
	// auth failure: false
}

// ExampleClaimsFrom shows a handler reading the verified Claims that the
// middleware attached to the request context.
func ExampleClaimsFrom() {
	ctx := auth.WithClaims(context.Background(), &auth.Claims{
		Subject: "alice@example.com",
		Scopes:  []string{"mcp:read", "mcp:write"},
	})

	claims, ok := auth.ClaimsFrom(ctx)
	if !ok {
		return // unauthenticated context — the middleware was bypassed
	}
	fmt.Println("subject:", claims.Subject)
	fmt.Println("scopes:", claims.Scopes)

	// Output:
	// subject: alice@example.com
	// scopes: [mcp:read mcp:write]
}

// ExampleAuthorizer shows composing a post-validation authorization policy from
// scope and claim predicates. An Authorizer runs against typed Claims -- for
// example at an MCP per-tool gate (see the transport/mcpauth ToolGate).
func ExampleAuthorizer() {
	// A tool that requires the mcp:write scope AND a clinician role.
	policy := auth.AllOf(
		auth.HasScopes("mcp:write"),
		auth.HasClaim("role", "clinician"),
	)

	clinician := &auth.Claims{
		Scopes: []string{"mcp:read", "mcp:write"},
		Raw:    map[string]string{"role": "clinician"},
	}
	auditor := &auth.Claims{
		Scopes: []string{"mcp:read", "mcp:write"},
		Raw:    map[string]string{"role": "auditor"},
	}

	fmt.Println("clinician allowed:", policy(context.Background(), clinician) == nil)
	fmt.Println("auditor allowed:", policy(context.Background(), auditor) == nil)

	// Output:
	// clinician allowed: true
	// auditor allowed: false
}

// ExampleNewMemorySessionStore shows the per-user concurrency cap: the third
// concurrent session for a user exceeds MaxConcurrentPerUser and is rejected.
func ExampleNewMemorySessionStore() {
	// Inject a deterministic id generator for a reproducible example; pass nil
	// in production to get cryptographically-random ids.
	var n int
	ids := func() string {
		n++
		return fmt.Sprintf("sess-%d", n)
	}

	store := auth.NewMemorySessionStore(auth.SessionConfig{
		MaxConcurrentPerUser: 2,
		Timeout:              time.Hour,
	}, ids)

	now := time.Now()
	a, _ := store.Open("alice", now)
	b, _ := store.Open("alice", now)
	_, err := store.Open("alice", now) // a third exceeds the cap

	fmt.Println("opened:", a, b)
	fmt.Println("third rejected:", errors.Is(err, auth.ErrSessionLimitExceeded))
	fmt.Println("alice sessions:", store.Count("alice", now))

	// Output:
	// opened: sess-1 sess-2
	// third rejected: true
	// alice sessions: 2
}
