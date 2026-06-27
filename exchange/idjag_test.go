package exchange_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/polyglotdev/mcp-auth-go/audit"
	"github.com/polyglotdev/mcp-auth-go/exchange"
)

// idjagResponse is a canned RFC 8693 step-1 response carrying an ID-JAG.
func idjagResponse(idjag string) string {
	return `{"access_token":"` + idjag + `","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag","token_type":"N_A","expires_in":300}`
}

// downstreamResponse is a canned RFC 7523 step-2 response carrying an access token.
func downstreamResponse(tok, scope string) string {
	return `{"access_token":"` + tok + `","token_type":"Bearer","expires_in":3600,"scope":"` + scope + `"}`
}

func TestExchangeIDJAGForm(t *testing.T) {
	tests := []struct {
		name               string
		subjectTokenType   string
		requestedTokenType string
		audience           string
		resource           string
		scope              []string
		wantSubjectType    string
		wantRequestedType  string // "" => the form must NOT carry requested_token_type
	}{
		{
			name:               "mint id-jag",
			subjectTokenType:   exchange.TokenTypeIDToken,
			requestedTokenType: exchange.TokenTypeIDJAG,
			audience:           "https://acme.chat.example/",
			resource:           "https://api.chat.example/",
			scope:              []string{"chat.read", "chat.history"},
			wantSubjectType:    exchange.TokenTypeIDToken,
			wantRequestedType:  exchange.TokenTypeIDJAG,
		},
		{
			name:              "back-compat: neither field set",
			wantSubjectType:   "urn:ietf:params:oauth:token-type:access_token",
			wantRequestedType: "", // must be absent
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotForm url.Values
			srv, _ := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				gotForm = r.Form
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(downstreamResponse("down", "")))
			})
			ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ex.Exchange(context.Background(), exchange.Request{
				SubjectToken:       "subj",
				SubjectTokenType:   tt.subjectTokenType,
				RequestedTokenType: tt.requestedTokenType,
				Audience:           tt.audience,
				Resource:           tt.resource,
				Scope:              tt.scope,
			})
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if got := gotForm.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
				t.Errorf("grant_type = %q", got)
			}
			if got := gotForm.Get("subject_token_type"); got != tt.wantSubjectType {
				t.Errorf("subject_token_type = %q, want %q", got, tt.wantSubjectType)
			}
			_, hasRequested := gotForm["requested_token_type"]
			if tt.wantRequestedType == "" {
				if hasRequested {
					t.Errorf("requested_token_type present (%q), want absent (back-compat)", gotForm.Get("requested_token_type"))
				}
			} else {
				if got := gotForm.Get("requested_token_type"); got != tt.wantRequestedType {
					t.Errorf("requested_token_type = %q, want %q", got, tt.wantRequestedType)
				}
			}
			if tt.audience != "" && gotForm.Get("audience") != tt.audience {
				t.Errorf("audience = %q, want %q", gotForm.Get("audience"), tt.audience)
			}
			if tt.resource != "" && gotForm.Get("resource") != tt.resource {
				t.Errorf("resource = %q, want %q", gotForm.Get("resource"), tt.resource)
			}
		})
	}
}

func TestRedeemAssertion(t *testing.T) {
	tests := []struct {
		name       string
		assertion  string
		scope      []string
		asStatus   int
		asBody     string
		wantHits   int
		wantToken  string
		wantScopes []string
		wantErr    error // nil => success
	}{
		{
			name:       "happy",
			assertion:  "idjag-assertion",
			scope:      []string{"chat.read"},
			asStatus:   200,
			asBody:     downstreamResponse("down", "chat.read"),
			wantHits:   1,
			wantToken:  "down",
			wantScopes: []string{"chat.read"},
		},
		{name: "empty assertion", assertion: "", wantHits: 0, wantErr: nil}, // wantErr handled specially below
		{name: "AS rejects", assertion: "idjag", asStatus: 400, asBody: `{"error":"invalid_grant"}`, wantHits: 1, wantErr: exchange.ErrExchangeRejected},
		{name: "AS unavailable", assertion: "idjag", asStatus: 503, wantHits: 1, wantErr: exchange.ErrExchangeUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotForm url.Values
			var gotAuth string
			srv, calls := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				gotForm = r.Form
				gotAuth = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				if tt.asStatus != 0 {
					w.WriteHeader(tt.asStatus)
				}
				_, _ = w.Write([]byte(tt.asBody))
			})
			ex, err := exchange.NewExchanger(exchange.Config{TokenURL: srv.URL, ClientAuth: exchange.BasicAuth{ClientID: "id", ClientSecret: "sec"}})
			if err != nil {
				t.Fatal(err)
			}
			tok, err := ex.RedeemAssertion(context.Background(), tt.assertion, tt.scope...)

			switch {
			case tt.assertion == "":
				if err == nil {
					t.Fatal("want error for empty assertion")
				}
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
			default:
				if err != nil {
					t.Fatalf("RedeemAssertion: %v", err)
				}
				if tok.AccessToken != tt.wantToken {
					t.Errorf("token = %q, want %q", tok.AccessToken, tt.wantToken)
				}
				if strings.Join(tok.Scopes, " ") != strings.Join(tt.wantScopes, " ") {
					t.Errorf("scopes = %v, want %v", tok.Scopes, tt.wantScopes)
				}
				if gotForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
					t.Errorf("grant_type = %q", gotForm.Get("grant_type"))
				}
				if gotForm.Get("assertion") != tt.assertion {
					t.Errorf("assertion = %q, want %q", gotForm.Get("assertion"), tt.assertion)
				}
				if !strings.HasPrefix(gotAuth, "Basic ") {
					t.Errorf("Authorization = %q, want Basic", gotAuth)
				}
			}
			if *calls != tt.wantHits {
				t.Errorf("AS hits = %d, want %d", *calls, tt.wantHits)
			}
		})
	}
}

func TestProvide(t *testing.T) {
	const idjag, downstream = "the-id-jag-jwt", "the-downstream-token"
	var idpForm url.Values
	var gotAssertion string
	idpSrv, _ := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idpForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(idjagResponse(idjag)))
	})
	rasSrv, _ := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotAssertion = r.Form.Get("assertion")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(downstreamResponse(downstream, "chat.read")))
	})
	p, err := exchange.NewDownstreamProvider(exchange.DownstreamConfig{
		IDP:        exchange.Endpoint{TokenURL: idpSrv.URL, ClientAuth: exchange.BasicAuth{ClientID: "idp"}},
		ResourceAS: exchange.Endpoint{TokenURL: rasSrv.URL, ClientAuth: exchange.BasicAuth{ClientID: "ras"}},
		Audience:   "https://acme.chat.example/",
		Resource:   "https://api.chat.example/",
		Scope:      []string{"chat.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := p.Provide(context.Background(), exchange.ProvideRequest{SubjectAssertion: "id-token", Subject: "user-1"})
	if err != nil {
		t.Fatalf("Provide: %v", err)
	}
	if tok.AccessToken != downstream {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, downstream)
	}
	if strings.Join(tok.Scopes, " ") != "chat.read" {
		t.Errorf("Scopes = %v", tok.Scopes)
	}
	if idpForm.Get("requested_token_type") != exchange.TokenTypeIDJAG {
		t.Errorf("IDP requested_token_type = %q", idpForm.Get("requested_token_type"))
	}
	if idpForm.Get("subject_token_type") != exchange.TokenTypeIDToken {
		t.Errorf("IDP subject_token_type = %q", idpForm.Get("subject_token_type"))
	}
	if idpForm.Get("audience") != "https://acme.chat.example/" {
		t.Errorf("IDP audience = %q", idpForm.Get("audience"))
	}
	if gotAssertion != idjag {
		t.Errorf("Resource AS assertion = %q, want the ID-JAG %q", gotAssertion, idjag)
	}
}

func TestProvideCache(t *testing.T) {
	tests := []struct {
		name          string
		subject       string
		withExpiresIn bool
		wantHitsFirst int // hits on each fake after the first Provide
		wantHitsTotal int // hits on each fake after two Provides
	}{
		{name: "cached", subject: "user-1", withExpiresIn: true, wantHitsFirst: 1, wantHitsTotal: 1},
		{name: "empty subject uncached", subject: "", withExpiresIn: true, wantHitsFirst: 1, wantHitsTotal: 2},
		{name: "no expires_in not cached", subject: "user-1", withExpiresIn: false, wantHitsFirst: 1, wantHitsTotal: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			body := `{"access_token":"down","token_type":"Bearer","scope":"chat.read"}`
			if tt.withExpiresIn {
				body = downstreamResponse("down", "chat.read")
			}
			idpSrv, ih := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(idjagResponse("idjag")))
			})
			rasSrv, rh := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			})
			sink := &recordingSink{}
			p, err := exchange.NewDownstreamProvider(exchange.DownstreamConfig{
				IDP:        exchange.Endpoint{TokenURL: idpSrv.URL, ClientAuth: exchange.BasicAuth{}},
				ResourceAS: exchange.Endpoint{TokenURL: rasSrv.URL, ClientAuth: exchange.BasicAuth{}},
				Audience:   "aud",
				Scope:      []string{"chat.read"},
				Cache:      exchange.NewMemoryCache(func() time.Time { return now }, 30*time.Second),
				Now:        func() time.Time { return now },
				Audit:      sink,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := exchange.ProvideRequest{SubjectAssertion: "id-token", Subject: tt.subject}
			if _, err := p.Provide(context.Background(), req); err != nil {
				t.Fatalf("first Provide: %v", err)
			}
			if *ih != tt.wantHitsFirst || *rh != tt.wantHitsFirst {
				t.Fatalf("after 1st Provide: idp=%d ras=%d, want %d each", *ih, *rh, tt.wantHitsFirst)
			}
			if _, err := p.Provide(context.Background(), req); err != nil {
				t.Fatalf("second Provide: %v", err)
			}
			if *ih != tt.wantHitsTotal || *rh != tt.wantHitsTotal {
				t.Fatalf("after 2nd Provide: idp=%d ras=%d, want %d each", *ih, *rh, tt.wantHitsTotal)
			}
			// Two Provides => exactly two granted events (a cache hit still audits).
			if len(sink.events) != 2 {
				t.Fatalf("audit events = %d, want 2", len(sink.events))
			}
			for i, e := range sink.events {
				if e.Outcome != audit.OutcomeGranted || e.ReasonCode != "cross_app_access" {
					t.Errorf("event %d = {%s %q}, want {granted cross_app_access}", i, e.Outcome, e.ReasonCode)
				}
				if strings.Join(e.Scopes, " ") != "chat.read" {
					t.Errorf("event %d scopes = %v, want [chat.read]", i, e.Scopes)
				}
			}
		})
	}
}

func TestProvideStepFailures(t *testing.T) {
	tests := []struct {
		name             string
		idpStatus        int
		idpBody          string
		cancelAfterStep1 bool
		rasStatus        int
		rasBody          string
		wantErr          error
		wantRASHits      int
		wantOutcome      audit.Outcome
		wantReason       string
	}{
		{name: "step1 rejects", idpStatus: 400, idpBody: `{"error":"invalid_request"}`, wantErr: exchange.ErrExchangeRejected, wantRASHits: 0, wantOutcome: audit.OutcomeDenied, wantReason: "exchange_rejected"},
		{name: "step1 5xx", idpStatus: 503, wantErr: exchange.ErrExchangeUnavailable, wantRASHits: 0, wantOutcome: audit.OutcomeError, wantReason: "exchange_unavailable"},
		{name: "step1 empty access_token", idpStatus: 200, idpBody: `{"access_token":"","token_type":"N_A"}`, wantErr: exchange.ErrExchangeRejected, wantRASHits: 0, wantOutcome: audit.OutcomeDenied, wantReason: "exchange_rejected"},
		{name: "ctx cancel between legs", idpStatus: 200, idpBody: idjagResponse("idjag"), cancelAfterStep1: true, wantErr: exchange.ErrExchangeUnavailable, wantRASHits: 0, wantOutcome: audit.OutcomeError, wantReason: "exchange_unavailable"},
		{name: "step2 rejects", idpStatus: 200, idpBody: idjagResponse("idjag"), rasStatus: 400, rasBody: `{"error":"invalid_grant"}`, wantErr: exchange.ErrExchangeRejected, wantRASHits: 1, wantOutcome: audit.OutcomeDenied, wantReason: "exchange_rejected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			idpSrv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.idpStatus)
				_, _ = w.Write([]byte(tt.idpBody))
				if tt.cancelAfterStep1 {
					cancel()
				}
			})
			rasSrv, rh := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tt.rasStatus != 0 {
					w.WriteHeader(tt.rasStatus)
				}
				_, _ = w.Write([]byte(tt.rasBody))
			})
			sink := &recordingSink{}
			p, err := exchange.NewDownstreamProvider(exchange.DownstreamConfig{
				IDP:        exchange.Endpoint{TokenURL: idpSrv.URL, ClientAuth: exchange.BasicAuth{}},
				ResourceAS: exchange.Endpoint{TokenURL: rasSrv.URL, ClientAuth: exchange.BasicAuth{}},
				Audience:   "aud",
				Audit:      sink,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Provide(ctx, exchange.ProvideRequest{SubjectAssertion: "id-token", Subject: "user-1"})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if *rh != tt.wantRASHits {
				t.Errorf("Resource AS hits = %d, want %d", *rh, tt.wantRASHits)
			}
			if len(sink.events) != 1 {
				t.Fatalf("audit events = %d, want exactly 1", len(sink.events))
			}
			if e := sink.events[0]; e.Outcome != tt.wantOutcome || e.ReasonCode != tt.wantReason {
				t.Errorf("event = {%s %q}, want {%s %q}", e.Outcome, e.ReasonCode, tt.wantOutcome, tt.wantReason)
			}
		})
	}
}

func TestProvideNoLeak(t *testing.T) {
	// Only the subject assertion and the ID-JAG can reach an error surface: the
	// issued downstream token only materializes on a 200 success, where Provide
	// returns (tok, nil) with no error path carrying the token.
	const (
		subjectMarker = "SUBJECT-ASSERTION-SECRET-zzz"
		idjagMarker   = "ID-JAG-SECRET-zzz"
	)
	tests := []struct {
		name      string
		idpStatus int
		idpBody   string
		rasStatus int
		rasBody   string
	}{
		{
			name:      "error_description echoes the assertion",
			idpStatus: 400,
			idpBody:   `{"error":"invalid_grant","error_description":"subject was ` + subjectMarker + `"}`,
		},
		{
			name:      "step2 error_description echoes the id-jag",
			idpStatus: 200,
			idpBody:   idjagResponse(idjagMarker),
			rasStatus: 400,
			rasBody:   `{"error":"invalid_grant","error_description":"assertion ` + idjagMarker + `"}`,
		},
		{
			name:      "decode failure echoes the assertion",
			idpStatus: 200,
			// Valid JSON, wrong shape: access_token as a number forces an
			// UnmarshalTypeError while "leak" echoes the assertion marker.
			idpBody: `{"access_token": 12345, "leak":"` + subjectMarker + `"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idpSrv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.idpStatus)
				_, _ = w.Write([]byte(tt.idpBody))
			})
			rasSrv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tt.rasStatus != 0 {
					w.WriteHeader(tt.rasStatus)
				}
				_, _ = w.Write([]byte(tt.rasBody))
			})
			p, err := exchange.NewDownstreamProvider(exchange.DownstreamConfig{
				IDP:        exchange.Endpoint{TokenURL: idpSrv.URL, ClientAuth: exchange.BasicAuth{}},
				ResourceAS: exchange.Endpoint{TokenURL: rasSrv.URL, ClientAuth: exchange.BasicAuth{}},
				Audience:   "aud",
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Provide(context.Background(), exchange.ProvideRequest{SubjectAssertion: subjectMarker, Subject: "user-1"})
			if err == nil {
				t.Fatal("want an error")
			}
			surfaces := []string{err.Error()}
			if u := errors.Unwrap(err); u != nil {
				surfaces = append(surfaces, u.Error())
			}
			for _, marker := range []string{subjectMarker, idjagMarker} {
				for _, s := range surfaces {
					if strings.Contains(s, marker) {
						t.Errorf("secret %q leaked into error surface: %s", marker, s)
					}
				}
			}
		})
	}
}

// TestProvideDPoP wires ONE shared *DPoP across both legs and asserts each leg's
// proof is htu-bound to its own endpoint (no cross-leg replay).
func TestProvideDPoP(t *testing.T) {
	var idpProof, rasProof string
	idpSrv, _ := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
		idpProof = r.Header.Get("DPoP")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(idjagResponse("idjag")))
	})
	rasSrv, _ := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
		rasProof = r.Header.Get("DPoP")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(downstreamResponse("down", "chat.read")))
	})
	dp, err := exchange.NewDPoP(exchange.BasicAuth{ClientID: "id", ClientSecret: "sec"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := exchange.NewDownstreamProvider(exchange.DownstreamConfig{
		IDP:        exchange.Endpoint{TokenURL: idpSrv.URL, ClientAuth: dp},
		ResourceAS: exchange.Endpoint{TokenURL: rasSrv.URL, ClientAuth: dp},
		Audience:   "aud",
		Scope:      []string{"chat.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Provide(context.Background(), exchange.ProvideRequest{SubjectAssertion: "id-token"}); err != nil {
		t.Fatalf("Provide: %v", err)
	}
	for _, leg := range []struct {
		name    string
		proof   string
		wantHTU string
	}{
		{"idp", idpProof, idpSrv.URL},
		{"ras", rasProof, rasSrv.URL},
	} {
		if leg.proof == "" {
			t.Errorf("%s: missing DPoP proof", leg.name)
			continue
		}
		msg, err := jws.Parse([]byte(leg.proof))
		if err != nil {
			t.Errorf("%s: parse proof: %v", leg.name, err)
			continue
		}
		var claims map[string]any
		if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
			t.Errorf("%s: unmarshal proof: %v", leg.name, err)
			continue
		}
		if claims["htu"] != leg.wantHTU {
			t.Errorf("%s: htu = %v, want %q (proof not bound to its own endpoint)", leg.name, claims["htu"], leg.wantHTU)
		}
	}
}

func TestNewDownstreamProvider(t *testing.T) {
	validIDP := exchange.Endpoint{TokenURL: "https://idp/token", ClientAuth: exchange.BasicAuth{}}
	validRAS := exchange.Endpoint{TokenURL: "https://ras/token", ClientAuth: exchange.BasicAuth{}}
	tests := []struct {
		name    string
		cfg     exchange.DownstreamConfig
		wantErr string // "" => ok
	}{
		{name: "missing IDP TokenURL", cfg: exchange.DownstreamConfig{IDP: exchange.Endpoint{ClientAuth: exchange.BasicAuth{}}, ResourceAS: validRAS, Audience: "aud"}, wantErr: "IDP.TokenURL"},
		{name: "missing IDP ClientAuth", cfg: exchange.DownstreamConfig{IDP: exchange.Endpoint{TokenURL: "https://idp/token"}, ResourceAS: validRAS, Audience: "aud"}, wantErr: "IDP.ClientAuth"},
		{name: "missing RAS TokenURL", cfg: exchange.DownstreamConfig{IDP: validIDP, ResourceAS: exchange.Endpoint{ClientAuth: exchange.BasicAuth{}}, Audience: "aud"}, wantErr: "ResourceAS.TokenURL"},
		{name: "missing RAS ClientAuth", cfg: exchange.DownstreamConfig{IDP: validIDP, ResourceAS: exchange.Endpoint{TokenURL: "https://ras/token"}, Audience: "aud"}, wantErr: "ResourceAS.ClientAuth"},
		{name: "missing Audience", cfg: exchange.DownstreamConfig{IDP: validIDP, ResourceAS: validRAS}, wantErr: "Audience"},
		{name: "valid", cfg: exchange.DownstreamConfig{IDP: validIDP, ResourceAS: validRAS, Audience: "aud"}, wantErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := exchange.NewDownstreamProvider(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// TestProvideDefaultSubjectTokenType confirms an unset SubjectTokenType defaults
// to TokenTypeIDToken on the wire.
func TestProvideDefaultSubjectTokenType(t *testing.T) {
	var gotSubjectType string
	idpSrv, _ := mockAS(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSubjectType = r.Form.Get("subject_token_type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(idjagResponse("idjag")))
	})
	rasSrv, _ := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(downstreamResponse("down", "")))
	})
	p, err := exchange.NewDownstreamProvider(exchange.DownstreamConfig{
		IDP:        exchange.Endpoint{TokenURL: idpSrv.URL, ClientAuth: exchange.BasicAuth{}},
		ResourceAS: exchange.Endpoint{TokenURL: rasSrv.URL, ClientAuth: exchange.BasicAuth{}},
		Audience:   "aud",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Provide(context.Background(), exchange.ProvideRequest{SubjectAssertion: "id-token"}); err != nil {
		t.Fatal(err)
	}
	if gotSubjectType != exchange.TokenTypeIDToken {
		t.Errorf("default subject_token_type = %q, want %q", gotSubjectType, exchange.TokenTypeIDToken)
	}
}

// nonEvictingCache is a Cache that stores entries forever (no staleness check),
// modeling a shared cache without independent TTL eviction. It isolates the
// provider's own !ExpiresAt.IsZero() gate, which MemoryCache's eviction would
// otherwise mask.
type nonEvictingCache struct {
	mu    sync.Mutex
	items map[string]*exchange.Token
}

func newNonEvictingCache() *nonEvictingCache {
	return &nonEvictingCache{items: map[string]*exchange.Token{}}
}

func (c *nonEvictingCache) Get(key string) (*exchange.Token, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tok, ok := c.items[key]
	return tok, ok
}

func (c *nonEvictingCache) Set(key string, tok *exchange.Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = tok
}

func (c *nonEvictingCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// TestProvideZeroExpiryNotCached pins the provider's own !ExpiresAt.IsZero()
// cache gate using a non-evicting cache: a final token with no expires_in must
// not be stored, so a second Provide runs both legs again.
func TestProvideZeroExpiryNotCached(t *testing.T) {
	idpSrv, ih := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(idjagResponse("idjag")))
	})
	rasSrv, rh := mockAS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No expires_in => zero ExpiresAt => must not be cached.
		_, _ = w.Write([]byte(`{"access_token":"down","token_type":"Bearer"}`))
	})
	cache := newNonEvictingCache()
	p, err := exchange.NewDownstreamProvider(exchange.DownstreamConfig{
		IDP:        exchange.Endpoint{TokenURL: idpSrv.URL, ClientAuth: exchange.BasicAuth{}},
		ResourceAS: exchange.Endpoint{TokenURL: rasSrv.URL, ClientAuth: exchange.BasicAuth{}},
		Audience:   "aud",
		Cache:      cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := exchange.ProvideRequest{SubjectAssertion: "id-token", Subject: "user-1"}
	if _, err := p.Provide(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Provide(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if cache.size() != 0 {
		t.Errorf("cache size = %d, want 0 (zero-expiry token must not be stored)", cache.size())
	}
	if *ih != 2 || *rh != 2 {
		t.Errorf("hits idp=%d ras=%d, want 2 each (zero-expiry => uncached)", *ih, *rh)
	}
}

func TestProvideConcurrency(t *testing.T) {
	tests := []struct {
		name      string
		withCache bool
	}{
		{name: "no cache", withCache: false},
		{name: "with cache", withCache: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Plain httptest servers (no shared hit counter) so 16 concurrent
			// Provides don't race on the mockAS counter.
			idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(idjagResponse("idjag")))
			}))
			defer idpSrv.Close()
			rasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(downstreamResponse("down", "chat.read")))
			}))
			defer rasSrv.Close()
			cfg := exchange.DownstreamConfig{
				IDP:        exchange.Endpoint{TokenURL: idpSrv.URL, ClientAuth: exchange.BasicAuth{}},
				ResourceAS: exchange.Endpoint{TokenURL: rasSrv.URL, ClientAuth: exchange.BasicAuth{}},
				Audience:   "aud",
				Scope:      []string{"chat.read"},
			}
			if tt.withCache {
				cfg.Cache = exchange.NewMemoryCache(time.Now, 30*time.Second)
			}
			p, err := exchange.NewDownstreamProvider(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					tok, err := p.Provide(context.Background(), exchange.ProvideRequest{SubjectAssertion: "id-token", Subject: "user-1"})
					if err != nil || tok.AccessToken != "down" {
						t.Errorf("Provide: tok=%v err=%v", tok, err)
					}
				}()
			}
			wg.Wait()
		})
	}
}
