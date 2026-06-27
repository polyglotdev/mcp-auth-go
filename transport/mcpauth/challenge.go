package mcpauth

// This file adds DPoP challenge/response shaping to the MCP Go SDK transport.
// The SDK's RequireBearerToken hard-codes a Bearer-schemed WWW-Authenticate and
// exposes no DPoP-Nonce hook, so challengeWriter wraps the response: on a DPoP
// enforcement failure it rewrites the challenge to the DPoP scheme (RFC 9449
// §7.1) and emits a DPoP-Nonce when one is demanded (§9), and on a successful
// response it rotates a fresh nonce (§8.2). The per-request classification
// travels from newVerifierFunc to the writer via a challengeState on the request
// context. Unwrap keeps the SDK's streaming (http.ResponseController Flush)
// transparent.

import (
	"context"
	"net/http"
	"strings"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/dpop"
)

// dpopChallenge builds a DPoP-scheme WWW-Authenticate value for a DPoP
// enforcement failure (RFC 9449 §7.1 / §9). code is invalid_dpop_proof or
// use_dpop_nonce; resource_metadata (RFC 9728) is appended when configured.
func dpopChallenge(code, resourceMetadataURL string) string {
	params := []string{`realm="mcp"`, `error="` + code + `"`}
	if resourceMetadataURL != "" {
		params = append(params, `resource_metadata="`+sanitizeQuoted(resourceMetadataURL)+`"`)
	}
	return "DPoP " + strings.Join(params, ", ")
}

// sanitizeQuoted strips characters that would break a quoted-string in a
// WWW-Authenticate header (RFC 7230 token grammar). Mirrors transport/http's
// helper of the same name; the per-transport copy keeps mcpauth from importing
// the http package's internals.
func sanitizeQuoted(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' || c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// challengeState records, per request, whether a DPoP enforcement failure
// occurred and which RFC 9449 §7.1/§9 error code applies. newVerifierFunc writes
// it (read from the request context); challengeWriter reads it at WriteHeader.
type challengeState struct {
	isDPoP bool
	code   string // auth.ErrInvalidDPoPProof.Code or auth.ErrUseDPoPNonce.Code
}

type challengeKey struct{}

// dpopChallengeMiddleware wraps the already-built SDK bearer middleware so a DPoP
// enforcement failure is answered with a DPoP-scheme WWW-Authenticate (+
// DPoP-Nonce) and a successful response rotates a nonce. It installs a per-request
// challengeState on the context (for the verifier to classify into) and a
// challengeWriter (to rewrite the response). dv is never nil here — the caller
// installs this only when DPoP is configured.
func dpopChallengeMiddleware(inner func(http.Handler) http.Handler, dv *dpop.Verifier, resourceMetadataURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		wrapped := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			st := &challengeState{}
			cw := &challengeWriter{ResponseWriter: w, st: st, dv: dv, resourceMetadataURL: resourceMetadataURL, now: time.Now}
			wrapped.ServeHTTP(cw, r.WithContext(context.WithValue(r.Context(), challengeKey{}, st)))
		})
	}
}

// challengeWriter rewrites the SDK middleware's challenge and rotates nonces. It
// implements Unwrap so http.ResponseController (the MCP SDK's streaming Flush)
// reaches the underlying writer.
type challengeWriter struct {
	http.ResponseWriter
	st                  *challengeState
	dv                  *dpop.Verifier
	resourceMetadataURL string
	now                 func() time.Time
	wroteHeader         bool
}

// Unwrap exposes the underlying ResponseWriter so http.NewResponseController can
// reach its Flush/deadline methods through this wrapper.
func (w *challengeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WriteHeader injects the DPoP challenge or rotation nonce exactly once, then
// delegates.
func (w *challengeWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.inject(code)
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write triggers the one-time injection (implicit 200) for handlers that write a
// body without an explicit WriteHeader, then delegates.
func (w *challengeWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *challengeWriter) inject(code int) {
	h := w.Header()
	switch {
	case w.st.isDPoP && code == http.StatusUnauthorized:
		// RFC 9449 §7.1/§9: correct the scheme to DPoP (Set replaces the SDK's
		// Bearer value) and mark the challenge uncacheable (parity w/ transport/http).
		h.Set("WWW-Authenticate", dpopChallenge(w.st.code, w.resourceMetadataURL))
		h.Set("Cache-Control", "no-store")
		if w.st.code == auth.ErrUseDPoPNonce.Code {
			if n := w.dv.IssueNonce(w.now()); n != "" {
				h.Set("DPoP-Nonce", n)
			}
		}
	case code >= 200 && code < 300 && w.dv.NonceConfigured():
		// RFC 9449 §8.2: rotate onto success; leave the handler's own Cache-Control
		// intact (e.g. the SDK's SSE "no-cache, no-transform").
		if n := w.dv.IssueNonce(w.now()); n != "" {
			h.Set("DPoP-Nonce", n)
			if h.Get("Cache-Control") == "" {
				h.Set("Cache-Control", "no-store")
			}
		}
	}
}
