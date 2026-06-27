package auth

import (
	"context"
	"testing"
)

// TestRawTokenFrom proves WithRawToken/RawTokenFrom round-trips a stashed
// token, and that an unstashed context reports the empty string and false
// rather than a stale or panicking value.
func TestRawTokenFrom(t *testing.T) {
	const token = "header.payload.sig"
	tests := []struct {
		name      string
		ctx       context.Context
		wantToken string
		wantOK    bool
	}{
		{
			name:      "present round-trips the stashed token",
			ctx:       WithRawToken(context.Background(), token),
			wantToken: token,
			wantOK:    true,
		},
		{
			name:      "absent returns empty and false",
			ctx:       context.Background(),
			wantToken: "",
			wantOK:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(st *testing.T) {
			got, ok := RawTokenFrom(tc.ctx)
			if got != tc.wantToken || ok != tc.wantOK {
				st.Fatalf("RawTokenFrom = %q, %v; want %q, %v", got, ok, tc.wantToken, tc.wantOK)
			}
		})
	}
}
