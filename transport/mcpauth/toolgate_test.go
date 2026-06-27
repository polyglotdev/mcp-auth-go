package mcpauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/audit"
	"github.com/polyglotdev/mcp-auth-go/internal/jwkstest"
	"github.com/polyglotdev/mcp-auth-go/transport/mcpauth"
)

// bearerRoundTripper adds an Authorization: Bearer header to every request, so a
// real MCP client authenticates through the bearer middleware.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (b bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(clone)
}

// TestToolGateEndToEnd drives a real MCP client through the full stack -- bearer
// auth, claims propagation, and the receiving-middleware gate -- to prove the
// SDK invokes the gate for an actual tools/call and that a denial reaches the
// client without the gated tool ever running.
func TestToolGateEndToEnd(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "0.0.1"}, nil)
	var toolRan bool
	mcp.AddTool(server, &mcp.Tool{Name: "write_rx", Description: "writes a prescription"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			toolRan = true
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
		})
	server.AddReceivingMiddleware(mcpauth.ToolGate{
		Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")},
	}.Middleware())

	httpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	ts := httptest.NewServer(mcpauth.RequireBearerToken(v, nil)(httpHandler))
	t.Cleanup(ts.Close)

	tests := []struct {
		name    string
		scope   string
		wantErr bool
		wantRan bool
	}{
		{name: "authorized", scope: "mcp:write", wantErr: false, wantRan: true},
		{name: "missing scope", scope: "mcp:read", wantErr: true, wantRan: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			toolRan = false
			token := j.Mint(t, jwkstest.ClaimSet{Subject: "alice", Private: map[string]any{"scope": tc.scope}})

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			httpClient := &http.Client{Transport: bearerRoundTripper{token: token, base: http.DefaultTransport}}
			transport := &mcp.StreamableClientTransport{
				Endpoint:             ts.URL,
				HTTPClient:           httpClient,
				DisableStandaloneSSE: true,
			}
			client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
			session, err := client.Connect(ctx, transport, nil)
			if err != nil {
				t.Fatalf("client.Connect: %v", err)
			}
			defer func() { _ = session.Close() }()

			_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "write_rx"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("CallTool err = %v, wantErr = %v", err, tc.wantErr)
			}
			if toolRan != tc.wantRan {
				t.Errorf("tool ran = %v, want %v", toolRan, tc.wantRan)
			}
		})
	}
}

// TestToolGateEndToEndDiscoveryFiltering drives a real MCP client's tools/list
// through the full stack to prove unauthorized tools are not even discoverable.
func TestToolGateEndToEndDiscoveryFiltering(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "0.0.1"}, nil)
	noop := func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
	}
	mcp.AddTool(server, &mcp.Tool{Name: "write_rx", Description: "writes a prescription"}, noop)
	mcp.AddTool(server, &mcp.Tool{Name: "read_chart", Description: "reads a chart"}, noop)
	server.AddReceivingMiddleware(mcpauth.ToolGate{
		Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")},
	}.Middleware())

	httpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	ts := httptest.NewServer(mcpauth.RequireBearerToken(v, nil)(httpHandler))
	t.Cleanup(ts.Close)

	tests := []struct {
		name  string
		scope string
		want  []string // sorted
	}{
		{name: "reader sees only read_chart", scope: "mcp:read", want: []string{"read_chart"}},
		{name: "writer sees both", scope: "mcp:write", want: []string{"read_chart", "write_rx"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := j.Mint(t, jwkstest.ClaimSet{Subject: "alice", Private: map[string]any{"scope": tc.scope}})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			httpClient := &http.Client{Transport: bearerRoundTripper{token: token, base: http.DefaultTransport}}
			transport := &mcp.StreamableClientTransport{Endpoint: ts.URL, HTTPClient: httpClient, DisableStandaloneSSE: true}
			session, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, transport, nil)
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}
			defer func() { _ = session.Close() }()

			res, err := session.ListTools(ctx, &mcp.ListToolsParams{})
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			var got []string
			for _, tool := range res.Tools {
				got = append(got, tool.Name)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("visible tools = %v, want %v", got, tc.want)
			}
		})
	}
}

// authedCtx returns a context carrying a caller with the given scopes.
func authedCtx(scopes ...string) context.Context {
	return auth.WithClaims(context.Background(), &auth.Claims{Scopes: scopes})
}

// callGate drives one method/tool through the gate's middleware with ctx,
// reporting whether the downstream handler was reached and any returned error.
func callGate(ctx context.Context, gate mcpauth.ToolGate, method, tool string) (reached bool, err error) {
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		reached = true
		return &mcp.CallToolResult{}, nil
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool}}
	_, err = gate.Middleware()(next)(ctx, method, req)
	return reached, err
}

// recordingSink is a local fake audit.Sink capturing events (mcpauth_test only;
// the audit_test capture is unexported and in another module).
type recordingSink struct{ events []audit.Event }

func (s *recordingSink) Record(_ context.Context, e audit.Event) { s.events = append(s.events, e) }

func TestToolGateEmitsAuditEvents(t *testing.T) {
	const tool = "read_record"
	tests := []struct {
		name        string
		policy      auth.Authorizer // policy for `tool`; nil => default-allow
		authed      bool
		wantOutcome audit.Outcome
		wantReason  string
	}{
		{name: "allow (default, no policy)", policy: nil, authed: true, wantOutcome: audit.OutcomeGranted, wantReason: ""},
		{name: "deny typed forbidden (secret cause)", policy: func(context.Context, *auth.Claims) error {
			return auth.ErrForbidden.With(errors.New(`claim "backend" != "secret-value"`))
		}, authed: true, wantOutcome: audit.OutcomeDenied, wantReason: "forbidden"},
		{name: "deny insufficient_scope", policy: auth.HasScopes("mcp:admin"), authed: true, wantOutcome: audit.OutcomeDenied, wantReason: "insufficient_scope"},
		{name: "deny plain (non-auth.Error) -> forbidden fallback", policy: func(context.Context, *auth.Claims) error {
			return errors.New("custom denial")
		}, authed: true, wantOutcome: audit.OutcomeDenied, wantReason: "forbidden"},
		{name: "unauthenticated", policy: nil, authed: false, wantOutcome: audit.OutcomeDenied, wantReason: "unauthenticated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &recordingSink{}
			gate := mcpauth.ToolGate{Audit: sink}
			if tt.policy != nil {
				gate.Policies = map[string]auth.Authorizer{tool: tt.policy}
			}
			ctx := context.Background()
			if tt.authed {
				ctx = authedCtx() // claims present, no scopes
			}
			_, _ = callGate(ctx, gate, "tools/call", tool)

			if len(sink.events) != 1 {
				t.Fatalf("want 1 event, got %d", len(sink.events))
			}
			e := sink.events[0]
			if e.Action != audit.ActionToolCall || e.Outcome != tt.wantOutcome || e.ReasonCode != tt.wantReason {
				t.Errorf("event = {%s %s %q}, want {tool_call %s %q}", e.Action, e.Outcome, e.ReasonCode, tt.wantOutcome, tt.wantReason)
			}
			if e.Tool != tool {
				t.Errorf("Tool = %q, want %q", e.Tool, tool)
			}
			for _, a := range append(e.MetricLabels(), e.TraceAttributes()...) {
				if strings.Contains(a.Value, "secret-value") {
					t.Errorf("cause text leaked into %s=%q", a.Key, a.Value)
				}
			}
		})
	}
}

func TestToolGateAttackerToolNotAMetricLabel(t *testing.T) {
	const evil = "../../../etc/passwd-attacker-chosen"
	sink := &recordingSink{}
	gate := mcpauth.ToolGate{Audit: sink}
	_, _ = callGate(context.Background(), gate, "tools/call", evil) // unauthenticated
	if len(sink.events) != 1 {
		t.Fatalf("want 1 event, got %d", len(sink.events))
	}
	for _, a := range sink.events[0].MetricLabels() {
		if a.Value == evil {
			t.Fatalf("attacker tool name %q became a metric label %q", evil, a.Key)
		}
	}
}

func TestToolGateAllowsAuthorizedToolCall(t *testing.T) {
	gate := mcpauth.ToolGate{Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")}}
	reached, err := callGate(authedCtx("mcp:write"), gate, "tools/call", "write_rx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reached {
		t.Error("authorized tool call did not reach the handler")
	}
}

func TestToolGateDeniesUnauthorizedToolCall(t *testing.T) {
	gate := mcpauth.ToolGate{Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")}}
	reached, err := callGate(authedCtx("mcp:read"), gate, "tools/call", "write_rx")
	if err == nil {
		t.Fatal("unauthorized tool call was allowed")
	}
	if reached {
		t.Error("handler ran despite denial")
	}
	if strings.Contains(err.Error(), "missing scope") {
		t.Errorf("denial error leaks the authorizer cause: %v", err)
	}
}

func TestToolGateAllowsUnlistedToolByDefault(t *testing.T) {
	gate := mcpauth.ToolGate{Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")}}
	reached, err := callGate(authedCtx("mcp:read"), gate, "tools/call", "read_patient") // unlisted
	if err != nil || !reached {
		t.Errorf("unlisted tool with nil Default should be allowed: reached=%v err=%v", reached, err)
	}
}

func TestToolGateDeniesUnlistedToolWhenDefaultDenies(t *testing.T) {
	gate := mcpauth.ToolGate{
		Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")},
		Default:  auth.DenyAll,
	}
	reached, err := callGate(authedCtx("mcp:read"), gate, "tools/call", "read_patient")
	if err == nil || reached {
		t.Errorf("unlisted tool with DenyAll default should be denied: reached=%v err=%v", reached, err)
	}
}

func TestToolGatePassesThroughNonToolMethods(t *testing.T) {
	gate := mcpauth.ToolGate{
		Policies: map[string]auth.Authorizer{"write_rx": auth.DenyAll},
		Default:  auth.DenyAll, // even a maximally restrictive gate...
	}
	// ...does not gate a method that is neither tools/call nor tools/list.
	reached, err := callGate(context.Background(), gate, "initialize", "")
	if err != nil || !reached {
		t.Errorf("initialize should pass through the gate: reached=%v err=%v", reached, err)
	}
}

func TestToolGateDeniesUnauthenticatedToolCall(t *testing.T) {
	gate := mcpauth.ToolGate{Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")}}
	reached, err := callGate(context.Background(), gate, "tools/call", "write_rx") // no claims
	if err == nil || reached {
		t.Errorf("tool call without an authenticated caller should be denied: reached=%v err=%v", reached, err)
	}
}

// TestToolGateDeniesUnauthenticatedUnlistedToolCall proves the gate fails closed
// for an unlisted (default-allow) tool too: with no authenticated caller there
// is no valid token, so even a default-allow tool is denied.
func TestToolGateDeniesUnauthenticatedUnlistedToolCall(t *testing.T) {
	gate := mcpauth.ToolGate{Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")}}
	reached, err := callGate(context.Background(), gate, "tools/call", "ping") // unlisted, no claims
	if err == nil || reached {
		t.Errorf("unlisted tool call without an authenticated caller should be denied: reached=%v err=%v", reached, err)
	}
}

// listThroughGate runs tools/list (returning toolNames, with a pagination
// cursor) through the gate with ctx, and returns the visible tool names.
func listThroughGate(ctx context.Context, gate mcpauth.ToolGate, toolNames ...string) []string {
	full := &mcp.ListToolsResult{NextCursor: "page-2"}
	for _, n := range toolNames {
		full.Tools = append(full.Tools, &mcp.Tool{Name: n})
	}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return full, nil }
	req := &mcp.ListToolsRequest{Params: &mcp.ListToolsParams{}}
	res, _ := gate.Middleware()(next)(ctx, "tools/list", req)
	ltr, _ := res.(*mcp.ListToolsResult)
	var out []string
	for _, tool := range ltr.Tools {
		out = append(out, tool.Name)
	}
	return out
}

func TestToolGateHidesUnauthorizedToolsFromList(t *testing.T) {
	gate := mcpauth.ToolGate{
		Policies: map[string]auth.Authorizer{
			"write_rx":   auth.HasScopes("mcp:write"),
			"read_chart": auth.HasScopes("mcp:read"),
		},
	}
	// Caller has mcp:read: sees read_chart and the unlisted ping, not write_rx.
	got := listThroughGate(authedCtx("mcp:read"), gate, "read_chart", "write_rx", "ping")
	want := []string{"read_chart", "ping"}
	if !slices.Equal(got, want) {
		t.Errorf("visible tools = %v, want %v", got, want)
	}
}

func TestToolGateListPreservesPaginationCursor(t *testing.T) {
	gate := mcpauth.ToolGate{Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")}}
	full := &mcp.ListToolsResult{NextCursor: "page-2", Tools: []*mcp.Tool{{Name: "write_rx"}, {Name: "ping"}}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return full, nil }
	req := &mcp.ListToolsRequest{Params: &mcp.ListToolsParams{}}
	res, _ := gate.Middleware()(next)(authedCtx("mcp:read"), "tools/list", req)
	ltr, ok := res.(*mcp.ListToolsResult)
	if !ok {
		t.Fatalf("result type = %T, want *mcp.ListToolsResult", res)
	}
	if ltr.NextCursor != "page-2" {
		t.Errorf("NextCursor = %q, want page-2 (pagination must survive filtering)", ltr.NextCursor)
	}
	if len(ltr.Tools) != 1 || ltr.Tools[0].Name != "ping" {
		t.Errorf("visible tools = %v, want [ping]", ltr.Tools)
	}
}

func TestToolGateListHidesAllWhenUnauthenticated(t *testing.T) {
	gate := mcpauth.ToolGate{Policies: map[string]auth.Authorizer{"write_rx": auth.HasScopes("mcp:write")}}
	// No claims: reveal nothing, including the unlisted ping (fail closed).
	got := listThroughGate(context.Background(), gate, "write_rx", "ping")
	if len(got) != 0 {
		t.Errorf("visible tools = %v, want none for an unauthenticated caller", got)
	}
}

// TestClaimsFromContextAfterBearer proves the full typed Claims (not a lossy
// view) rides from the verifier through to a downstream handler's context.
func TestClaimsFromContextAfterBearer(t *testing.T) {
	j := jwkstest.New(t)
	v := newValidator(t, j)

	var got *auth.Claims
	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = mcpauth.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := mcpauth.RequireBearerToken(v, nil)(next)

	token := j.Mint(t, jwkstest.ClaimSet{
		Subject: "alice",
		Email:   "alice@example.com",
		Private: map[string]any{"role": "clinician", "scope": "mcp:read"},
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body)
	}
	if !ok || got == nil {
		t.Fatal("ClaimsFromContext found no claims after a valid bearer token")
	}
	if got.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", got.Subject)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com (full claims must propagate)", got.Email)
	}
	if got.Raw["role"] != "clinician" {
		t.Errorf("Raw[role] = %q, want clinician", got.Raw["role"])
	}
}

// TestClaimsFromContextAbsent proves the accessor reports absence cleanly when
// no verifier ran.
func TestClaimsFromContextAbsent(t *testing.T) {
	if c, ok := mcpauth.ClaimsFromContext(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok || c != nil {
		t.Errorf("ClaimsFromContext on a bare context = (%v, %v), want (nil, false)", c, ok)
	}
}

// TestClaimsFromContextViaWithClaims proves the accessor also honors claims set
// under the core's context key (auth.WithClaims) -- the path used by in-memory
// transports, custom middleware, and tests that inject a caller directly.
func TestClaimsFromContextViaWithClaims(t *testing.T) {
	claims := &auth.Claims{Subject: "bob", Scopes: []string{"mcp:read"}}
	ctx := auth.WithClaims(context.Background(), claims)
	got, ok := mcpauth.ClaimsFromContext(ctx)
	if !ok || got != claims {
		t.Fatalf("ClaimsFromContext = (%v, %v), want the injected claims", got, ok)
	}
}
