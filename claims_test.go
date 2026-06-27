package auth

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TestClaimsConfirmation verifies claimsFromToken extracts the cnf.jkt
// thumbprint into Claims.Confirmation across cnf shapes, and that the nested
// cnf object never leaks into Raw (the Raw loop only copies string claims).
func TestClaimsConfirmation(t *testing.T) {
	tests := []struct {
		name string
		cnf  any // value for the cnf claim; nil => no cnf claim is set
		want string
	}{
		{name: "cnf.jkt present", cnf: map[string]any{"jkt": "abc123"}, want: "abc123"},
		{name: "cnf without jkt", cnf: map[string]any{"x": "y"}, want: ""},
		{name: "cnf absent leaves it empty", cnf: nil, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			tok, err := jwt.NewBuilder().Subject("user-1").Build()
			if err != nil {
				st.Fatalf("build token: %v", err)
			}
			if tc.cnf != nil {
				if err := tok.Set("cnf", tc.cnf); err != nil {
					st.Fatalf("set cnf: %v", err)
				}
			}
			c := claimsFromToken(tok)
			if c.Confirmation != tc.want {
				st.Errorf("Confirmation = %q; want %q", c.Confirmation, tc.want)
			}
			if _, ok := c.Raw["cnf"]; ok {
				st.Error("cnf must not leak into Raw")
			}
		})
	}
}
