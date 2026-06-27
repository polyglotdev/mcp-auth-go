package mcpauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/polyglotdev/mcp-auth-go/dpop"
)

func TestDPoPChallenge(t *testing.T) {
	tests := []struct {
		name string
		code string
		url  string
		want string
	}{
		{name: "invalid_dpop_proof, no metadata", code: "invalid_dpop_proof", url: "", want: `DPoP realm="mcp", error="invalid_dpop_proof"`},
		{name: "use_dpop_nonce, no metadata", code: "use_dpop_nonce", url: "", want: `DPoP realm="mcp", error="use_dpop_nonce"`},
		{name: "with resource_metadata", code: "invalid_dpop_proof", url: "https://mcp.example/.well-known/oauth-protected-resource", want: `DPoP realm="mcp", error="invalid_dpop_proof", resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"`},
		{name: "metadata with stray quote is sanitized", code: "use_dpop_nonce", url: `https://x/"q`, want: `DPoP realm="mcp", error="use_dpop_nonce", resource_metadata="https://x/q"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dpopChallenge(tt.code, tt.url); got != tt.want {
				t.Errorf("dpopChallenge(%q, %q) = %q, want %q", tt.code, tt.url, got, tt.want)
			}
		})
	}
}

func TestChallengeWriterInjectHeaders(t *testing.T) {
	ns, err := dpop.NewSignedNonce(make([]byte, 32), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	plainDV := dpop.NewVerifier(dpop.Config{})
	nonceDV := dpop.NewVerifier(dpop.Config{Nonce: ns})
	fixedNow := func() time.Time { return time.Unix(1000, 0) }

	tests := []struct {
		name            string
		isDPoP          bool
		code            string
		status          int
		dv              *dpop.Verifier
		preCacheControl string
		wantWWWPrefix   string // "" = we set no WWW-Authenticate
		wantError       string // substring; "" = none
		wantNonce       bool
		wantCacheCtrl   string
	}{
		{name: "invalid_dpop_proof 401", isDPoP: true, code: "invalid_dpop_proof", status: 401, dv: plainDV, wantWWWPrefix: "DPoP ", wantError: `error="invalid_dpop_proof"`, wantNonce: false, wantCacheCtrl: "no-store"},
		{name: "use_dpop_nonce 401", isDPoP: true, code: "use_dpop_nonce", status: 401, dv: nonceDV, wantWWWPrefix: "DPoP ", wantError: `error="use_dpop_nonce"`, wantNonce: true, wantCacheCtrl: "no-store"},
		{name: "non-dpop 401 untouched", isDPoP: false, status: 401, dv: plainDV, wantWWWPrefix: "", wantNonce: false, wantCacheCtrl: ""},
		{name: "rotate 200, nonce, no pre-cc", isDPoP: false, status: 200, dv: nonceDV, wantNonce: true, wantCacheCtrl: "no-store"},
		{name: "rotate 200, nonce, pre-cc preserved", isDPoP: false, status: 200, dv: nonceDV, preCacheControl: "no-cache, no-transform", wantNonce: true, wantCacheCtrl: "no-cache, no-transform"},
		{name: "200, no nonce, no rotation", isDPoP: false, status: 200, dv: plainDV, wantNonce: false, wantCacheCtrl: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if tt.preCacheControl != "" {
				rec.Header().Set("Cache-Control", tt.preCacheControl)
			}
			cw := &challengeWriter{ResponseWriter: rec, st: &challengeState{isDPoP: tt.isDPoP, code: tt.code}, dv: tt.dv, now: fixedNow}
			cw.WriteHeader(tt.status)

			gotWWW := rec.Header().Get("WWW-Authenticate")
			if tt.wantWWWPrefix == "" {
				if gotWWW != "" {
					t.Errorf("WWW-Authenticate = %q, want none", gotWWW)
				}
			} else if !strings.HasPrefix(gotWWW, tt.wantWWWPrefix) || !strings.Contains(gotWWW, tt.wantError) {
				t.Errorf("WWW-Authenticate = %q, want prefix %q containing %q", gotWWW, tt.wantWWWPrefix, tt.wantError)
			}
			if gotNonce := rec.Header().Get("DPoP-Nonce") != ""; gotNonce != tt.wantNonce {
				t.Errorf("DPoP-Nonce present = %v, want %v", gotNonce, tt.wantNonce)
			}
			if got := rec.Header().Get("Cache-Control"); got != tt.wantCacheCtrl {
				t.Errorf("Cache-Control = %q, want %q", got, tt.wantCacheCtrl)
			}
		})
	}
}

func TestChallengeWriterPreservesFlush(t *testing.T) {
	ns, err := dpop.NewSignedNonce(make([]byte, 32), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	rec := httptest.NewRecorder() // implements Flush() and sets .Flushed
	cw := &challengeWriter{ResponseWriter: rec, st: &challengeState{}, dv: dpop.NewVerifier(dpop.Config{Nonce: ns}), now: func() time.Time { return time.Unix(1000, 0) }}

	rc := http.NewResponseController(cw)
	if _, err := cw.Write([]byte("data: hi\n\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rc.Flush(); err != nil {
		t.Fatalf("Flush through wrapper: %v", err)
	}
	if !rec.Flushed {
		t.Fatal("Flush did not reach the underlying writer via Unwrap()")
	}
	if rec.Header().Get("DPoP-Nonce") == "" {
		t.Fatal("rotation DPoP-Nonce missing on the streamed 200")
	}
}
