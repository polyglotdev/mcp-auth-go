package exchange_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/audit"
	"github.com/polyglotdev/mcp-auth-go/exchange"
)

// mockAS starts a test HTTP server, counts calls, and delegates to handler.
func mockAS(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// recordingSink is a local fake audit.Sink (exchange_test only).
type recordingSink struct{ events []audit.Event }

func (s *recordingSink) Record(_ context.Context, e audit.Event) { s.events = append(s.events, e) }

func TestExchangeEmitsAuditEvents(t *testing.T) {
	const subjectToken, accessToken = "SUBJECT-TOKEN-SECRET", "ISSUED-ACCESS-TOKEN-SECRET"
	tests := []struct {
		name        string
		asStatus    int    // AS HTTP status
		asScope     string // response `scope` ("" => omitted)
		asError     string // OAuth error code ("" => success)
		wantOutcome audit.Outcome
		wantReason  string
		wantScopes  []string
	}{
		{name: "success with scope", asStatus: 200, asScope: "downstream:read", wantOutcome: audit.OutcomeGranted, wantScopes: []string{"downstream:read"}},
		{name: "success, AS omits scope", asStatus: 200, asScope: "", wantOutcome: audit.OutcomeGranted, wantScopes: nil},
		{name: "AS rejects", asStatus: 400, asError: "access_denied", wantOutcome: audit.OutcomeDenied, wantReason: "exchange_rejected"},
		{name: "AS unavailable (5xx)", asStatus: 503, wantOutcome: audit.OutcomeError, wantReason: "exchange_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &recordingSink{}
			srv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.asStatus)
				switch {
				case tt.asError != "":
					_ = json.NewEncoder(w).Encode(map[string]string{"error": tt.asError})
				case tt.asStatus == 200:
					body := map[string]string{"access_token": accessToken, "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"}
					if tt.asScope != "" {
						body["scope"] = tt.asScope
					}
					_ = json.NewEncoder(w).Encode(body)
				}
			})
			ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}, Audit: sink})
			if err != nil {
				t.Fatalf("NewExchanger: %v", err)
			}
			_, _ = ex.Exchange(context.Background(), exchange.Request{SubjectToken: subjectToken, Subject: "sub-1", Audience: "aud"})

			if len(sink.events) != 1 {
				t.Fatalf("want 1 event, got %d", len(sink.events))
			}
			e := sink.events[0]
			if e.Action != audit.ActionTokenExchange || e.Outcome != tt.wantOutcome || e.ReasonCode != tt.wantReason {
				t.Errorf("event = {%s %s %q}, want {token_exchange %s %q}", e.Action, e.Outcome, e.ReasonCode, tt.wantOutcome, tt.wantReason)
			}
			if e.Subject != "sub-1" || e.Audience != "aud" {
				t.Errorf("identity = {%q %q}, want {sub-1 aud}", e.Subject, e.Audience)
			}
			if strings.Join(e.Scopes, " ") != strings.Join(tt.wantScopes, " ") {
				t.Errorf("Scopes = %v, want %v", e.Scopes, tt.wantScopes)
			}
			for _, secret := range []string{subjectToken, accessToken} {
				for _, a := range e.TraceAttributes() {
					if strings.Contains(a.Value, secret) {
						t.Errorf("token leaked into %s=%q", a.Key, a.Value)
					}
				}
			}
		})
	}
}

func TestExchangeAuditCacheHitEmitsGranted(t *testing.T) {
	sink := &recordingSink{}
	srv, calls := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600,"scope":"downstream:read"}`))
	})
	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}, Audit: sink})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	req := exchange.Request{SubjectToken: "s", Subject: "sub-1", Audience: "aud"}
	_, _ = ex.Exchange(context.Background(), req)
	_, _ = ex.Exchange(context.Background(), req) // cache hit: no second AS call

	if *calls != 1 {
		t.Fatalf("AS calls = %d, want 1 (second is a cache hit)", *calls)
	}
	if len(sink.events) != 2 {
		t.Fatalf("want 2 granted events (fresh + cache hit), got %d", len(sink.events))
	}
	for i, e := range sink.events {
		if e.Outcome != audit.OutcomeGranted {
			t.Errorf("event %d outcome = %s, want granted", i, e.Outcome)
		}
	}
}

func TestExchangeHappyPath(t *testing.T) {
	srv, _ := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"down","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600,"scope":"d:read"}`))
	})
	now := time.Unix(1000, 0)
	ex, err := exchange.NewExchanger(exchange.Config{
		TokenURL:   srv.URL,
		ClientAuth: exchange.BasicAuth{ClientID: "id", ClientSecret: "sec"},
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ex.Exchange(context.Background(), exchange.Request{SubjectToken: "subj"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "down" || tok.TokenType != "Bearer" {
		t.Fatalf("token = %+v", tok)
	}
	if !tok.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v", tok.ExpiresAt)
	}
}

func TestExchangeRejectsEmptySubjectToken(t *testing.T) {
	ex, _ := exchange.NewExchanger(exchange.Config{TokenURL: "https://as/token", ClientAuth: exchange.BasicAuth{}})
	if _, err := ex.Exchange(context.Background(), exchange.Request{}); err == nil {
		t.Fatal("want error for empty SubjectToken")
	}
}

func TestExchangeCacheHitAvoidsSecondCall(t *testing.T) {
	srv, calls := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"down","token_type":"Bearer","expires_in":3600}`))
	})
	ex, _ := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	req := exchange.Request{SubjectToken: "s", Subject: "user-1", Audience: "aud"}
	_, _ = ex.Exchange(context.Background(), req)
	_, _ = ex.Exchange(context.Background(), req)
	if *calls != 1 {
		t.Fatalf("AS called %d times; want 1 (cache hit)", *calls)
	}
}

func TestExchangeOAuthErrorRejected(t *testing.T) {
	srv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_target","error_description":"audience not permitted"}`))
	})
	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ex.Exchange(context.Background(), exchange.Request{SubjectToken: "s"})
	if !errors.Is(err, exchange.ErrExchangeRejected) {
		t.Fatalf("want ErrExchangeRejected, got %v", err)
	}
}

func TestExchangeServerErrorUnavailable(t *testing.T) {
	srv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ex.Exchange(context.Background(), exchange.Request{SubjectToken: "s"})
	if !errors.Is(err, exchange.ErrExchangeUnavailable) {
		t.Fatalf("want ErrExchangeUnavailable, got %v", err)
	}
}

func TestExchangeNoExpiresInNotCached(t *testing.T) {
	srv, calls := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No expires_in — token should NOT be cached.
		_, _ = w.Write([]byte(`{"access_token":"down","token_type":"Bearer"}`))
	})
	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	req := exchange.Request{SubjectToken: "s", Subject: "user-1", Audience: "aud"}
	_, _ = ex.Exchange(context.Background(), req)
	_, _ = ex.Exchange(context.Background(), req)
	if *calls != 2 {
		t.Fatalf("AS called %d times; want 2 (no expires_in => not cached)", *calls)
	}
}

func TestExchangeIsolatesCallers(t *testing.T) {
	srv, calls := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"down","token_type":"Bearer","expires_in":3600}`))
	})
	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	req1 := exchange.Request{SubjectToken: "s1", Subject: "user-1", Audience: "aud"}
	req2 := exchange.Request{SubjectToken: "s2", Subject: "user-2", Audience: "aud"}
	if _, err := ex.Exchange(context.Background(), req1); err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Exchange(context.Background(), req2); err != nil {
		t.Fatal(err)
	}
	// Each caller is a distinct cache key — both must hit the AS.
	if *calls != 2 {
		t.Fatalf("AS called %d times; want 2 (cross-caller isolation)", *calls)
	}
}

// TestExchangeDPoPNonceRetry verifies the one-shot use_dpop_nonce retry path
// end-to-end via Exchanger.do. The mock AS demands a nonce on the first call
// (400 use_dpop_nonce + DPoP-Nonce header) and succeeds on the second. The test
// asserts success and confirms the second request's DPoP proof carried the
// server-supplied nonce.
func TestExchangeDPoPNonceRetry(t *testing.T) {
	const serverNonce = "retryNonce42"
	attempt := 0
	var secondProof string

	srv, _ := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			// First attempt: demand a nonce.
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("DPoP-Nonce", serverNonce)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		// Second attempt: capture the DPoP proof and succeed.
		secondProof = r.Header.Get("DPoP")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"down","token_type":"DPoP","expires_in":3600}`))
	})

	d, err := exchange.NewDPoP(exchange.BasicAuth{ClientID: "id", ClientSecret: "sec"})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: d})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ex.Exchange(context.Background(), exchange.Request{SubjectToken: "subj"})
	if err != nil {
		t.Fatalf("exchange with nonce retry: %v", err)
	}
	if tok.AccessToken != "down" {
		t.Fatalf("token = %+v", tok)
	}
	if attempt != 2 {
		t.Fatalf("AS called %d times; want 2 (nonce retry)", attempt)
	}
	// The second proof must contain the server-supplied nonce.
	if secondProof == "" {
		t.Fatal("second request missing DPoP header")
	}
	msg, err := jws.Parse([]byte(secondProof))
	if err != nil {
		t.Fatalf("parse second DPoP proof: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		t.Fatalf("unmarshal second proof payload: %v", err)
	}
	if claims["nonce"] != serverNonce {
		t.Fatalf("second proof nonce = %v; want %q", claims["nonce"], serverNonce)
	}
}

// TestNoTokenInErrorOrLog is a secret-hygiene regression guard. It drives an
// AS rejection containing secret-looking text in error_description, and an AS
// unavailable case, and asserts that the subject token ("secret-subject-token")
// appears neither in err.Error() nor in the JSON-encoded *auth.Error body nor
// in a captured slog log output.
func TestNoTokenInErrorOrLog(t *testing.T) {
	const secretToken = "secret-subject-token"

	// Capture slog output.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// --- Rejected case ---
	rejectedSrv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		// error_description intentionally looks like it might contain something
		// sensitive; it must stay in Cause only, never in Message or the JSON body.
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"token was ` + secretToken + `"}`))
	})
	exRejected, err := exchange.NewExchanger(exchange.Config{
		TokenURL:   rejectedSrv.URL,
		ClientAuth: exchange.BasicAuth{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, rejectedErr := exRejected.Exchange(context.Background(), exchange.Request{SubjectToken: secretToken})
	if rejectedErr == nil {
		t.Fatal("expected error from rejected exchange")
	}

	// --- Unavailable case ---
	unavailSrv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	exUnavail, err := exchange.NewExchanger(exchange.Config{
		TokenURL:   unavailSrv.URL,
		ClientAuth: exchange.BasicAuth{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, unavailErr := exUnavail.Exchange(context.Background(), exchange.Request{SubjectToken: secretToken})
	if unavailErr == nil {
		t.Fatal("expected error from unavailable AS")
	}

	// Log both errors via slog (simulating what a handler might do).
	logger.Error("exchange rejected", slog.Any("err", rejectedErr))
	logger.Error("exchange unavailable", slog.Any("err", unavailErr))

	// Encode both *auth.Error values to JSON (what a transport would write to
	// the response body).
	var rejectedBody, unavailBody []byte
	var ae *auth.Error
	if errors.As(rejectedErr, &ae) {
		rejectedBody, _ = json.Marshal(ae)
	}
	if errors.As(unavailErr, &ae) {
		unavailBody, _ = json.Marshal(ae)
	}

	for _, s := range []struct {
		label string
		value string
	}{
		{"rejected err.Error()", rejectedErr.Error()},
		{"unavail err.Error()", unavailErr.Error()},
		{"rejected JSON body", string(rejectedBody)},
		{"unavail JSON body", string(unavailBody)},
		{"slog output", logBuf.String()},
	} {
		if strings.Contains(s.value, secretToken) {
			t.Errorf("secret token leaked into %s:\n%s", s.label, s.value)
		}
	}
}

// TestExchangeContextFreeNoSubject verifies that Exchange with context.Background()
// and no Subject (empty string) performs the exchange without touching the cache.
func TestExchangeContextFreeNoSubject(t *testing.T) {
	srv, calls := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"down","token_type":"Bearer","expires_in":3600}`))
	})
	ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	// No Subject → uncached; two calls must both reach the AS.
	req := exchange.Request{SubjectToken: "s"}
	if _, err := ex.Exchange(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Exchange(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Fatalf("AS called %d times; want 2 (empty Subject => uncached)", *calls)
	}
}
