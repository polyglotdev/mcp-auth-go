package exchange_test

import (
	"errors"
	"strings"
	"testing"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/exchange"
)

func TestRejectedMatchesSentinelAndHidesDescription(t *testing.T) {
	err := exchange.Rejected("invalid_grant", "subject token secret-ish detail")
	if !errors.Is(err, exchange.ErrExchangeRejected) {
		t.Fatal("Rejected() must match ErrExchangeRejected by code")
	}
	var ae *auth.Error
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "invalid_grant") {
		t.Fatalf("message must name the AS error code, got %q", ae.Message)
	}
	// error_description is discarded entirely by Rejected (it is AS-controlled and
	// can echo request content, including tokens); it must never reach Message or Cause.
	if strings.Contains(ae.Message, "secret-ish") {
		t.Fatal("error_description must not appear in Message")
	}
	if ae.Cause != nil {
		t.Fatalf("error_description must be discarded, not wrapped as Cause; got %v", ae.Cause)
	}
}
