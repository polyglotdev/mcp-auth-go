package auth_test

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// TestErrorIsSentinel proves that wrapping a sentinel *Error with a cause
// still matches the original sentinel via errors.Is, and that a different
// sentinel does not.
func TestErrorIsSentinel(t *testing.T) {
	wrapped := auth.ErrForbidden.With(errors.New("claim tier=none"))
	if !errors.Is(wrapped, auth.ErrForbidden) {
		t.Errorf("wrapped error should still match the sentinel via errors.Is")
	}
	if errors.Is(wrapped, auth.ErrInvalidToken) {
		t.Errorf("different code must NOT match")
	}
}

// TestErrorPreservesHTTPStatus asserts each sentinel exposes the right HTTP
// status code, and that wrapping with a cause preserves it. A regression here
// would silently downgrade a 403 to a 500 in handler responses.
func TestErrorPreservesHTTPStatus(t *testing.T) {
	tests := []struct {
		name     string
		sentinel *auth.Error
		want     int
	}{
		{name: "invalid token is 401", sentinel: auth.ErrInvalidToken, want: http.StatusUnauthorized},
		{name: "expired token is 401", sentinel: auth.ErrExpiredToken, want: http.StatusUnauthorized},
		{name: "missing token is 401", sentinel: auth.ErrMissingToken, want: http.StatusUnauthorized},
		{name: "forbidden is 403", sentinel: auth.ErrForbidden, want: http.StatusForbidden},
		{name: "insufficient scope is 403", sentinel: auth.ErrInsufficientScope, want: http.StatusForbidden},
		{name: "session limit exceeded is 429", sentinel: auth.ErrSessionLimitExceeded, want: http.StatusTooManyRequests},
		{name: "rate limit exceeded is 429", sentinel: auth.ErrRateLimitExceeded, want: http.StatusTooManyRequests},
		{name: "use dpop nonce is 401", sentinel: auth.ErrUseDPoPNonce, want: http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sentinel.HTTPStatus != tc.want {
				t.Errorf("%s status = %d, want %d", tc.sentinel.Code, tc.sentinel.HTTPStatus, tc.want)
			}
			wrapped := tc.sentinel.With(errors.New("x"))
			if wrapped.HTTPStatus != tc.want {
				t.Errorf("wrapped %s status = %d, want %d", tc.sentinel.Code, wrapped.HTTPStatus, tc.want)
			}
		})
	}
}

// TestErrorMessage proves Error() surfaces the sentinel code and, when set, the
// wrapped cause (what operators see in server logs), and never stringifies a
// nil cause as "<nil>" when Cause is unset.
func TestErrorMessage(t *testing.T) {
	tests := []struct {
		name    string
		err     *auth.Error
		want    []string // substrings that must be present
		notWant []string // substrings that must be absent
	}{
		{
			name: "with cause surfaces code and cause",
			err:  auth.ErrInvalidToken.With(fmt.Errorf("simulated jwx failure")),
			want: []string{"invalid_token", "simulated jwx failure"},
		},
		{
			name:    "without cause surfaces code but not <nil>",
			err:     auth.ErrForbidden,
			want:    []string{"forbidden"},
			notWant: []string{"<nil>"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.err.Error()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("Error() = %q, missing %q", got, w)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("Error() = %q, should not contain %q", got, nw)
				}
			}
		})
	}
}

// TestErrInvalidDPoPProof verifies the sentinel has the correct HTTP status,
// machine-readable code, and that errors.Is still matches a wrapped copy by
// code -- so a transport can identify it without coupling to the cause string.
func TestErrInvalidDPoPProof(t *testing.T) {
	if auth.ErrInvalidDPoPProof.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", auth.ErrInvalidDPoPProof.HTTPStatus)
	}
	if auth.ErrInvalidDPoPProof.Code != "invalid_dpop_proof" {
		t.Fatalf("code = %q", auth.ErrInvalidDPoPProof.Code)
	}
	// A wrapped copy still matches by code; the cause never reaches the body.
	wrapped := auth.ErrInvalidDPoPProof.With(errors.New("ath mismatch"))
	if !errors.Is(wrapped, auth.ErrInvalidDPoPProof) {
		t.Fatal("wrapped copy must match sentinel by code")
	}
}

// TestErrUseDPoPNonce verifies the use_dpop_nonce sentinel's code and that a
// wrapped copy is identified by errors.Is as use_dpop_nonce but NOT as
// invalid_dpop_proof -- the transport keys on this distinction to choose the
// retry-with-nonce challenge over the give-up one.
func TestErrUseDPoPNonce(t *testing.T) {
	if auth.ErrUseDPoPNonce.Code != "use_dpop_nonce" {
		t.Fatalf("code = %q, want use_dpop_nonce", auth.ErrUseDPoPNonce.Code)
	}

	wrapped := auth.ErrUseDPoPNonce.With(errors.New("missing nonce"))
	tests := []struct {
		name   string
		target *auth.Error
		want   bool
	}{
		{name: "matches use_dpop_nonce", target: auth.ErrUseDPoPNonce, want: true},
		{name: "distinct from invalid_dpop_proof", target: auth.ErrInvalidDPoPProof, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := errors.Is(wrapped, tc.target); got != tc.want {
				t.Errorf("errors.Is(wrapped, %s) = %v, want %v", tc.target.Code, got, tc.want)
			}
		})
	}
}

// TestForbiddenBodyHidesCause is an authorization guard: the sentinel's body
// must NOT leak the cause. A verbose error could tell an attacker which claim
// failed validation.
func TestForbiddenBodyHidesCause(t *testing.T) {
	cause := errors.New("sub=alice tier=external")
	wrapped := auth.ErrForbidden.With(cause)
	if wrapped.Message != auth.ErrForbidden.Message {
		t.Errorf("Message was rewritten when wrapping with cause: %q", wrapped.Message)
	}
	if strings.Contains(wrapped.Message, "external") {
		t.Errorf("cause leaked into Message: %q", wrapped.Message)
	}
}
