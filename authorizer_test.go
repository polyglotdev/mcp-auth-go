package auth_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/polyglotdev/mcp-auth-go"
)

func TestHasScopes(t *testing.T) {
	tests := []struct {
		name     string
		required []string
		granted  []string
		wantErr  bool
	}{
		{name: "all present", required: []string{"mcp:read", "mcp:write"}, granted: []string{"mcp:read", "mcp:write", "extra"}, wantErr: false},
		{name: "exact match", required: []string{"mcp:read"}, granted: []string{"mcp:read"}, wantErr: false},
		{name: "missing one", required: []string{"mcp:read", "mcp:write"}, granted: []string{"mcp:read"}, wantErr: true},
		{name: "none granted", required: []string{"mcp:read"}, granted: nil, wantErr: true},
		{name: "no requirement is a no-op", required: nil, granted: nil, wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			authz := auth.HasScopes(tc.required...)
			err := authz(context.Background(), &auth.Claims{Scopes: tc.granted})
			if tc.wantErr {
				if !errors.Is(err, auth.ErrInsufficientScope) {
					st.Fatalf("err = %v, want ErrInsufficientScope", err)
				}
				return
			}
			if err != nil {
				st.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHasAnyScope(t *testing.T) {
	tests := []struct {
		name    string
		any     []string
		granted []string
		wantErr bool
	}{
		{name: "one of many present", any: []string{"mcp:write", "mcp:admin"}, granted: []string{"mcp:read", "mcp:admin"}, wantErr: false},
		{name: "none present", any: []string{"mcp:write", "mcp:admin"}, granted: []string{"mcp:read"}, wantErr: true},
		{name: "no options is a no-op", any: nil, granted: nil, wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			err := auth.HasAnyScope(tc.any...)(context.Background(), &auth.Claims{Scopes: tc.granted})
			if tc.wantErr {
				if !errors.Is(err, auth.ErrInsufficientScope) {
					st.Fatalf("err = %v, want ErrInsufficientScope", err)
				}
				return
			}
			if err != nil {
				st.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHasClaim(t *testing.T) {
	claims := &auth.Claims{Raw: map[string]string{"role": "clinician", "tenant": "acme"}}
	tests := []struct {
		name        string
		claim, want string
		wantErr     bool
	}{
		{name: "match", claim: "role", want: "clinician", wantErr: false},
		{name: "value mismatch", claim: "role", want: "nurse", wantErr: true},
		{name: "missing claim", claim: "department", want: "cardiology", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			err := auth.HasClaim(tc.claim, tc.want)(context.Background(), claims)
			if tc.wantErr {
				if !errors.Is(err, auth.ErrForbidden) {
					st.Fatalf("err = %v, want ErrForbidden", err)
				}
				return
			}
			if err != nil {
				st.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAllOf(t *testing.T) {
	pass := auth.Authorizer(func(context.Context, *auth.Claims) error { return nil })
	fail := auth.Authorizer(func(context.Context, *auth.Claims) error { return auth.ErrForbidden })
	tests := []struct {
		name        string
		authorizers []auth.Authorizer
		wantErr     bool
	}{
		{name: "all pass", authorizers: []auth.Authorizer{pass, pass}, wantErr: false},
		{name: "one fails", authorizers: []auth.Authorizer{pass, fail}, wantErr: true},
		{name: "empty vacuously allows", authorizers: nil, wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			err := auth.AllOf(tc.authorizers...)(context.Background(), &auth.Claims{})
			if tc.wantErr {
				if !errors.Is(err, auth.ErrForbidden) {
					st.Errorf("AllOf = %v, want ErrForbidden", err)
				}
				return
			}
			if err != nil {
				st.Errorf("AllOf = %v, want nil", err)
			}
		})
	}
}

func TestAllOfShortCircuits(t *testing.T) {
	reached := false
	fail := auth.Authorizer(func(context.Context, *auth.Claims) error { return auth.ErrForbidden })
	spy := auth.Authorizer(func(context.Context, *auth.Claims) error { reached = true; return nil })

	_ = auth.AllOf(fail, spy)(context.Background(), &auth.Claims{})
	if reached {
		t.Error("AllOf did not short-circuit: the authorizer after a failure ran")
	}
}

func TestAnyOf(t *testing.T) {
	pass := auth.Authorizer(func(context.Context, *auth.Claims) error { return nil })
	fail := auth.Authorizer(func(context.Context, *auth.Claims) error { return auth.ErrForbidden })
	tests := []struct {
		name        string
		authorizers []auth.Authorizer
		wantErr     bool
	}{
		{name: "first fails second passes", authorizers: []auth.Authorizer{fail, pass}, wantErr: false},
		{name: "all fail", authorizers: []auth.Authorizer{fail, fail}, wantErr: true},
		{name: "empty vacuously denies", authorizers: nil, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			err := auth.AnyOf(tc.authorizers...)(context.Background(), &auth.Claims{})
			if tc.wantErr {
				if !errors.Is(err, auth.ErrForbidden) {
					st.Errorf("AnyOf = %v, want ErrForbidden", err)
				}
				return
			}
			if err != nil {
				st.Errorf("AnyOf = %v, want nil", err)
			}
		})
	}
}

func TestAllowAllDenyAll(t *testing.T) {
	tests := []struct {
		name    string
		authz   auth.Authorizer
		wantErr bool
	}{
		{name: "AllowAll allows", authz: auth.AllowAll, wantErr: false},
		{name: "DenyAll denies", authz: auth.DenyAll, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			err := tc.authz(context.Background(), &auth.Claims{})
			if tc.wantErr {
				if !errors.Is(err, auth.ErrForbidden) {
					st.Errorf("%s = %v, want ErrForbidden", tc.name, err)
				}
				return
			}
			if err != nil {
				st.Errorf("%s = %v, want nil", tc.name, err)
			}
		})
	}
}
