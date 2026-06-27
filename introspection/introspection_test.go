package introspection_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/introspection"
)

const (
	testIssuer   = "https://issuer.test"
	testAudience = "https://rs.test"
	fixedNowUnix = 1_700_000_000
	futureExp    = 1_700_003_600 // fixedNowUnix + 3600
)

// introspection.Validator must satisfy the core TokenValidator seam so it drops
// into both transports unchanged.
var _ auth.TokenValidator = (*introspection.Validator)(nil)

// recordingAS is a fake RFC 7662 introspection endpoint: it returns a fixed
// status + body and records the received request for assertions.
type recordingAS struct {
	server   *httptest.Server
	mu       sync.Mutex
	hits     int
	lastForm url.Values
	lastAuth string
}

func newRecordingAS(t *testing.T, status int, body string) *recordingAS {
	t.Helper()
	as := &recordingAS{}
	as.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		as.mu.Lock()
		as.hits++
		as.lastForm = form
		as.lastAuth = r.Header.Get("Authorization")
		as.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(as.server.Close)
	return as
}

func (as *recordingAS) hitCount() int {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.hits
}

func (as *recordingAS) snapshot() (form url.Values, authHeader string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.lastForm, as.lastAuth
}

func baseConfig(rawURL string) introspection.Config {
	return introspection.Config{
		IntrospectionURL: rawURL,
		ClientAuth:       introspection.BasicAuth{ClientID: "cid", ClientSecret: "csec"},
		Issuer:           testIssuer,
		Audience:         testAudience,
		Now:              func() time.Time { return time.Unix(fixedNowUnix, 0) },
	}
}

func mustValidator(t *testing.T, cfg introspection.Config) *introspection.Validator {
	t.Helper()
	v, err := introspection.NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func TestValidate(t *testing.T) {
	const tok = "opaque-tok"
	tests := []struct {
		name    string
		body    string
		bearer  string
		wantErr error
		// success expectations (checked only when wantErr == nil)
		sub       string
		iss       string
		aud       []string
		scopes    []string
		email     string
		cnf       string
		rawKey    string
		rawVal    string
		rawAbsent []string // keys that must NOT appear in Raw (non-string or skip-set)
		exp       int64    // expected ExpiresAt unix; 0 = not asserted
		iat       int64    // expected IssuedAt unix; 0 = not asserted
	}{
		{
			name: "active all claims",
			body: `{"active":true,"sub":"u1","iss":"https://issuer.test","aud":"https://rs.test",` +
				`"scope":"a b","email":"e@x.test","cnf":{"jkt":"thumb"},"exp":1700003600,"iat":1699999000,` +
				`"team":"blue","count":5,"client_id":"app1"}`,
			bearer: tok,
			sub:    "u1", iss: testIssuer, aud: []string{testAudience}, scopes: []string{"a", "b"},
			email: "e@x.test", cnf: "thumb", rawKey: "team", rawVal: "blue",
			rawAbsent: []string{"count", "client_id"}, // count: non-string dropped; client_id: skip-set
			exp:       1700003600, iat: 1699999000,
		},
		{
			name:   "active aud array",
			body:   `{"active":true,"iss":"https://issuer.test","aud":["https://other.test","https://rs.test"]}`,
			bearer: tok,
			iss:    testIssuer, aud: []string{"https://other.test", testAudience},
		},
		{name: "inactive", body: `{"active":false}`, bearer: tok, wantErr: auth.ErrInvalidToken},
		{name: "aud not matching", body: `{"active":true,"iss":"https://issuer.test","aud":"https://wrong.test"}`, bearer: tok, wantErr: auth.ErrInvalidToken},
		{name: "aud empty plus nonmatching", body: `{"active":true,"iss":"https://issuer.test","aud":["","https://other.test"]}`, bearer: tok, wantErr: auth.ErrInvalidToken},
		{name: "aud null", body: `{"active":true,"iss":"https://issuer.test","aud":null}`, bearer: tok, wantErr: auth.ErrInvalidToken},
		{name: "iss mismatch", body: `{"active":true,"iss":"https://evil.test","aud":"https://rs.test"}`, bearer: tok, wantErr: auth.ErrInvalidToken},
		{name: "iss absent", body: `{"active":true,"aud":"https://rs.test"}`, bearer: tok, wantErr: auth.ErrInvalidToken},
		{name: "aud absent", body: `{"active":true,"iss":"https://issuer.test"}`, bearer: tok, wantErr: auth.ErrInvalidToken},
		{name: "expired far past", body: `{"active":true,"iss":"https://issuer.test","aud":"https://rs.test","exp":1}`, bearer: tok, wantErr: auth.ErrExpiredToken},
		// exp boundary: fixedNowUnix=1700000000, ClockSkew default 30s.
		{name: "exp within skew still valid", body: `{"active":true,"iss":"https://issuer.test","aud":"https://rs.test","exp":1699999990}`, bearer: tok, iss: testIssuer, aud: []string{testAudience}, exp: 1699999990},
		{name: "exp outside skew expired", body: `{"active":true,"iss":"https://issuer.test","aud":"https://rs.test","exp":1699999969}`, bearer: tok, wantErr: auth.ErrExpiredToken},
		{name: "empty bearer", body: `{"active":true}`, bearer: "", wantErr: auth.ErrMissingToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := newRecordingAS(t, http.StatusOK, tt.body)
			v := mustValidator(t, baseConfig(as.server.URL))
			claims, err := v.Validate(context.Background(), tt.bearer)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want errors.Is %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if claims.Subject != tt.sub {
				t.Errorf("Subject = %q, want %q", claims.Subject, tt.sub)
			}
			if claims.Issuer != tt.iss {
				t.Errorf("Issuer = %q, want %q", claims.Issuer, tt.iss)
			}
			if !slices.Equal(claims.Audience, tt.aud) {
				t.Errorf("Audience = %v, want %v", claims.Audience, tt.aud)
			}
			if !slices.Equal(claims.Scopes, tt.scopes) {
				t.Errorf("Scopes = %v, want %v", claims.Scopes, tt.scopes)
			}
			if claims.Email != tt.email {
				t.Errorf("Email = %q, want %q", claims.Email, tt.email)
			}
			if claims.Confirmation != tt.cnf {
				t.Errorf("Confirmation = %q, want %q", claims.Confirmation, tt.cnf)
			}
			if tt.rawKey != "" && claims.Raw[tt.rawKey] != tt.rawVal {
				t.Errorf("Raw[%q] = %q, want %q", tt.rawKey, claims.Raw[tt.rawKey], tt.rawVal)
			}
			for _, k := range tt.rawAbsent {
				if v, ok := claims.Raw[k]; ok {
					t.Errorf("Raw[%q] = %q, want absent (non-string or skip-set member)", k, v)
				}
			}
			if tt.exp > 0 && claims.ExpiresAt.Unix() != tt.exp {
				t.Errorf("ExpiresAt = %d, want %d", claims.ExpiresAt.Unix(), tt.exp)
			}
			if tt.iat > 0 && claims.IssuedAt.Unix() != tt.iat {
				t.Errorf("IssuedAt = %d, want %d", claims.IssuedAt.Unix(), tt.iat)
			}
		})
	}
}

func TestValidateUnavailable(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		closeServer bool
	}{
		{name: "5xx", status: http.StatusInternalServerError, body: `{"active":true}`},
		{name: "401 bad client auth", status: http.StatusUnauthorized, body: `{"error":"invalid_client"}`},
		{name: "400 active true not trusted", status: http.StatusBadRequest, body: `{"active":true,"iss":"https://issuer.test","aud":"https://rs.test"}`},
		{name: "200 invalid json", status: http.StatusOK, body: `{not json`},
		{name: "200 malformed aud type", status: http.StatusOK, body: `{"active":true,"iss":"https://issuer.test","aud":123}`},
		{name: "transport error", closeServer: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rawURL string
			if tt.closeServer {
				s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				rawURL = s.URL
				s.Close()
			} else {
				as := newRecordingAS(t, tt.status, tt.body)
				rawURL = as.server.URL
			}
			v := mustValidator(t, baseConfig(rawURL))
			_, err := v.Validate(context.Background(), "tok")
			if !errors.Is(err, introspection.ErrIntrospectionUnavailable) {
				t.Fatalf("err = %v, want ErrIntrospectionUnavailable", err)
			}
		})
	}
}

func TestValidateRequestShape(t *testing.T) {
	tests := []struct {
		name            string
		clientAuth      introspection.ClientAuthenticator
		wantBasicHeader bool
		wantClientBody  bool
	}{
		{name: "basic", clientAuth: introspection.BasicAuth{ClientID: "cid", ClientSecret: "csec"}, wantBasicHeader: true},
		{name: "formpost", clientAuth: introspection.FormPost{ClientID: "cid", ClientSecret: "csec"}, wantClientBody: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := newRecordingAS(t, http.StatusOK, `{"active":true,"iss":"https://issuer.test","aud":"https://rs.test"}`)
			cfg := baseConfig(as.server.URL)
			cfg.ClientAuth = tt.clientAuth
			v := mustValidator(t, cfg)
			if _, err := v.Validate(context.Background(), "opaque-tok"); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			form, authHeader := as.snapshot()
			if got := form.Get("token"); got != "opaque-tok" {
				t.Errorf("form token = %q, want opaque-tok", got)
			}
			if got := form.Get("token_type_hint"); got != "access_token" {
				t.Errorf("token_type_hint = %q, want access_token", got)
			}
			if tt.wantBasicHeader && !strings.HasPrefix(authHeader, "Basic ") {
				t.Errorf("Authorization = %q, want Basic ...", authHeader)
			}
			if tt.wantClientBody && form.Get("client_id") != "cid" {
				t.Errorf("body client_id = %q, want cid", form.Get("client_id"))
			}
			if !tt.wantClientBody && form.Get("client_secret") != "" {
				t.Errorf("client_secret leaked into body: %q", form.Get("client_secret"))
			}
		})
	}
}

func TestValidateNoLeak(t *testing.T) {
	const marker = "opaque-marker-12345"
	tests := []struct {
		name      string
		body      string
		wantCause string
	}{
		{name: "inactive echoes token", body: `{"active":false,"error_description":"token opaque-marker-12345 not found"}`, wantCause: "token inactive"},
		{name: "wrong aud echoes token", body: `{"active":true,"iss":"https://issuer.test","aud":"https://wrong.test","username":"opaque-marker-12345"}`, wantCause: "audience mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := newRecordingAS(t, http.StatusOK, tt.body)
			v := mustValidator(t, baseConfig(as.server.URL))
			_, err := v.Validate(context.Background(), marker)
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("err = %v, want ErrInvalidToken", err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("err.Error() leaks token marker: %q", err.Error())
			}
			cause := errors.Unwrap(err)
			if cause == nil {
				t.Fatal("expected a wrapped cause")
			}
			if strings.Contains(cause.Error(), marker) {
				t.Errorf("cause leaks token marker: %q", cause.Error())
			}
			if cause.Error() != tt.wantCause {
				t.Errorf("cause = %q, want %q", cause.Error(), tt.wantCause)
			}
		})
	}
}

func TestValidateCache(t *testing.T) {
	now := time.Unix(fixedNowUnix, 0)
	nowFn := func() time.Time { return now }

	as := newRecordingAS(t, http.StatusOK,
		`{"active":true,"iss":"https://issuer.test","aud":"https://rs.test","exp":1700003600}`)
	cfg := baseConfig(as.server.URL)
	cfg.Now = nowFn
	cfg.Cache = introspection.NewMemoryCache(nowFn, 30*time.Second)
	v := mustValidator(t, cfg)

	for i := 0; i < 2; i++ {
		if _, err := v.Validate(context.Background(), "tok"); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	}
	if got := as.hitCount(); got != 1 {
		t.Fatalf("hits = %d, want 1 (second call cached)", got)
	}

	// Advance into the leeway window [ExpiresAt-30s, ExpiresAt): the entry is
	// stale even though the token has not technically expired. This pins the
	// -leeway subtraction in MemoryCache.Get (a leeway of 0 would keep it fresh).
	now = time.Unix(futureExp-10, 0)
	if _, err := v.Validate(context.Background(), "tok"); err != nil {
		t.Fatalf("Validate after leeway: %v", err)
	}
	if got := as.hitCount(); got != 2 {
		t.Fatalf("hits = %d, want 2 (cache entry stale within leeway window)", got)
	}

	// A response without exp is never cached: every call hits the AS.
	as2 := newRecordingAS(t, http.StatusOK, `{"active":true,"iss":"https://issuer.test","aud":"https://rs.test"}`)
	cfg2 := baseConfig(as2.server.URL)
	cfg2.Cache = introspection.NewMemoryCache(cfg2.Now, 30*time.Second)
	v2 := mustValidator(t, cfg2)
	for i := 0; i < 2; i++ {
		if _, err := v2.Validate(context.Background(), "tok"); err != nil {
			t.Fatalf("Validate (no exp): %v", err)
		}
	}
	if got := as2.hitCount(); got != 2 {
		t.Fatalf("no-exp hits = %d, want 2 (never cached)", got)
	}
}

func TestCacheDeepCopy(t *testing.T) {
	c := introspection.NewMemoryCache(func() time.Time { return time.Unix(fixedNowUnix, 0) }, 30*time.Second)
	orig := &auth.Claims{
		Subject:   "u1",
		Audience:  []string{"a"},
		Scopes:    []string{"s"},
		Raw:       map[string]string{"k": "v"},
		ExpiresAt: time.Unix(futureExp, 0),
	}
	c.Set("key", orig)

	// Mutating the value passed to Set must not corrupt the stored entry.
	orig.Raw["k"] = "ORIG_MUT"

	got, ok := c.Get("key")
	if !ok {
		t.Fatal("expected cache hit")
	}
	// Mutating the value returned by Get must not corrupt the stored entry.
	got.Audience[0] = "MUT"
	got.Scopes = append(got.Scopes, "extra")
	got.Raw["k"] = "MUT"
	got.Raw["new"] = "x"

	again, ok := c.Get("key")
	if !ok {
		t.Fatal("expected second cache hit")
	}
	if again.Audience[0] != "a" {
		t.Errorf("Audience corrupted: %v", again.Audience)
	}
	if !slices.Equal(again.Scopes, []string{"s"}) {
		t.Errorf("Scopes corrupted: %v", again.Scopes)
	}
	if again.Raw["k"] != "v" {
		t.Errorf("Raw[k] corrupted: %q", again.Raw["k"])
	}
	if _, exists := again.Raw["new"]; exists {
		t.Errorf("Raw gained a key from caller mutation")
	}
}

func TestValidateConcurrency(t *testing.T) {
	// Run the -race sweep on BOTH the no-cache path (every goroutine does the
	// full HTTP round-trip + decode + claims build, with no cache mutex
	// serializing them) and the cached path (spec M9: with AND without a Cache).
	for _, withCache := range []bool{false, true} {
		name := "no cache"
		if withCache {
			name = "with cache"
		}
		t.Run(name, func(t *testing.T) {
			as := newRecordingAS(t, http.StatusOK,
				`{"active":true,"sub":"u1","iss":"https://issuer.test","aud":"https://rs.test","scope":"a b","exp":1700003600}`)
			cfg := baseConfig(as.server.URL)
			if withCache {
				cfg.Cache = introspection.NewMemoryCache(cfg.Now, 30*time.Second)
			}
			v := mustValidator(t, cfg)

			var wg sync.WaitGroup
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					claims, err := v.Validate(context.Background(), "tok")
					if err != nil {
						t.Errorf("Validate: %v", err)
						return
					}
					if claims.Subject != "u1" {
						t.Errorf("Subject = %q, want u1", claims.Subject)
					}
				}()
			}
			wg.Wait()
		})
	}
}

func TestNewValidator(t *testing.T) {
	ca := introspection.BasicAuth{ClientID: "c", ClientSecret: "s"}
	tests := []struct {
		name    string
		cfg     introspection.Config
		wantErr string // substring; "" means success
	}{
		{
			name:    "valid https",
			cfg:     introspection.Config{IntrospectionURL: "https://issuer.test/introspect", ClientAuth: ca, Issuer: testIssuer, Audience: testAudience},
			wantErr: "",
		},
		{
			name:    "missing url",
			cfg:     introspection.Config{ClientAuth: ca, Issuer: testIssuer, Audience: testAudience},
			wantErr: "IntrospectionURL is required",
		},
		{
			name:    "missing clientauth",
			cfg:     introspection.Config{IntrospectionURL: "https://issuer.test/introspect", Issuer: testIssuer, Audience: testAudience},
			wantErr: "ClientAuth is required",
		},
		{
			name:    "missing issuer",
			cfg:     introspection.Config{IntrospectionURL: "https://issuer.test/introspect", ClientAuth: ca, Audience: testAudience},
			wantErr: "Issuer is required",
		},
		{
			name:    "missing audience",
			cfg:     introspection.Config{IntrospectionURL: "https://issuer.test/introspect", ClientAuth: ca, Issuer: testIssuer},
			wantErr: "Audience is required",
		},
		{
			name:    "http non-loopback rejected",
			cfg:     introspection.Config{IntrospectionURL: "http://issuer.test/introspect", ClientAuth: ca, Issuer: testIssuer, Audience: testAudience},
			wantErr: "must be https",
		},
		{
			name:    "http loopback ip ok",
			cfg:     introspection.Config{IntrospectionURL: "http://127.0.0.1:9000/introspect", ClientAuth: ca, Issuer: testIssuer, Audience: testAudience},
			wantErr: "",
		},
		{
			name:    "http localhost ok",
			cfg:     introspection.Config{IntrospectionURL: "http://localhost:9000/introspect", ClientAuth: ca, Issuer: testIssuer, Audience: testAudience},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := introspection.NewValidator(tt.cfg)
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
