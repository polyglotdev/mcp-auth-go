package mcpauth

import (
	"context"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth "github.com/polyglotdev/mcp-auth-go"
	"github.com/polyglotdev/mcp-auth-go/audit"
)

// MCP JSON-RPC method names. The SDK's equivalents are unexported, so they are
// duplicated here; the gate's tests exercise real method names to catch drift.
const (
	methodCallTool  = "tools/call"
	methodListTools = "tools/list"
)

// errUnauthenticated is returned for a tools/call that reaches the gate without
// an authenticated caller -- a sign the bearer middleware was bypassed.
var errUnauthenticated = errors.New("forbidden: request is not authenticated")

// ToolGate is per-tool authorization for an MCP server. Install it with
//
//	server.AddReceivingMiddleware(gate.Middleware())
//
// It runs after the bearer middleware has authenticated the caller and, using
// the caller's [auth.Claims] (read with [ClaimsFromContext]), does two things:
//
//   - authorizes each tools/call, rejecting an unauthorized one with a JSON-RPC
//     error before the tool runs;
//   - filters tools/list so a caller only discovers the tools it may use.
//
// Both fail closed: with no authenticated caller, a tools/call is denied and
// tools/list reveals nothing. Methods other than these two pass through, since
// the bearer middleware already authenticated them.
type ToolGate struct {
	// Policies maps a tool name to the [auth.Authorizer] that must allow before
	// the tool runs (or is listed). A tool absent from the map is governed by
	// Default.
	Policies map[string]auth.Authorizer

	// Default authorizes tools not present in Policies. A nil Default allows
	// them (they still required a valid token). Set it to [auth.DenyAll] to fail
	// closed -- every callable tool must then have an explicit policy.
	Default auth.Authorizer

	// Audit, when set, records one [audit.Event] per tools/call decision
	// (granted or denied). nil disables auditing with zero overhead.
	Audit audit.Sink

	// Now supplies the decision timestamp for audit events; it defaults to
	// time.Now. It is a public field because ToolGate has no constructor.
	Now func() time.Time
}

// Middleware returns the MCP receiving middleware that enforces the gate.
func (g ToolGate) Middleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case methodCallTool:
				return g.gateCall(ctx, next, method, req)
			case methodListTools:
				return g.filterList(ctx, next, method, req)
			default:
				return next(ctx, method, req)
			}
		}
	}
}

// gateCall authorizes a single tools/call, denying it with a JSON-RPC error when
// the caller may not invoke the named tool. It fails closed: no caller, no call.
func (g ToolGate) gateCall(ctx context.Context, next mcp.MethodHandler, method string, req mcp.Request) (mcp.Result, error) {
	params, ok := req.GetParams().(*mcp.CallToolParamsRaw)
	if !ok {
		return next(ctx, method, req)
	}
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		g.record(ctx, audit.Event{
			Action: audit.ActionToolCall, Outcome: audit.OutcomeDenied,
			Tool: params.Name, ReasonCode: "unauthenticated", Time: g.now(),
		})
		return nil, errUnauthenticated
	}
	if err := g.evaluate(ctx, claims, params.Name); err != nil {
		g.record(ctx, g.toolEvent(claims, params.Name, audit.OutcomeDenied, reasonOf(err)))
		return nil, denial(err)
	}
	g.record(ctx, g.toolEvent(claims, params.Name, audit.OutcomeGranted, ""))
	return next(ctx, method, req)
}

// record sends e to the configured sink, if any (best-effort, nil ⇒ no-op).
func (g ToolGate) record(ctx context.Context, e audit.Event) {
	if g.Audit != nil {
		g.Audit.Record(ctx, e)
	}
}

// now returns the configured clock, defaulting to time.Now.
func (g ToolGate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// toolEvent builds a tool_call Event from the caller's claims. Tool reaches only
// span attributes, never a metric label (audit.Event.MetricLabels excludes it).
func (g ToolGate) toolEvent(claims *auth.Claims, tool string, outcome audit.Outcome, reason string) audit.Event {
	return audit.Event{
		Action: audit.ActionToolCall, Outcome: outcome, ReasonCode: reason, Tool: tool,
		Subject: claims.Subject, Issuer: claims.Issuer, Scopes: claims.Scopes,
		Email: claims.Email, Time: g.now(),
	}
}

// reasonOf extracts a stable code from a denial error: the *auth.Error.Code when
// present, else "forbidden" (mirroring denial). It never reads err.Error() /
// Message / Cause, so an authorizer's input-bearing cause can't reach a label.
func reasonOf(err error) string {
	var ae *auth.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return "forbidden"
}

// filterList drops from a tools/list response every tool the caller may not use,
// so unauthorized tools are not discoverable. With no authenticated caller it
// reveals nothing. The pagination cursor is preserved, so filtering composes
// with the server's paging (each page is filtered independently).
func (g ToolGate) filterList(ctx context.Context, next mcp.MethodHandler, method string, req mcp.Request) (mcp.Result, error) {
	res, err := next(ctx, method, req)
	if err != nil {
		return res, err
	}
	full, ok := res.(*mcp.ListToolsResult)
	if !ok {
		return res, nil
	}

	visible := &mcp.ListToolsResult{Meta: full.Meta, NextCursor: full.NextCursor}
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return visible, nil
	}
	for _, tool := range full.Tools {
		if g.evaluate(ctx, claims, tool.Name) == nil {
			visible.Tools = append(visible.Tools, tool)
		}
	}
	return visible, nil
}

// evaluate runs the policy governing tool against claims, returning nil when the
// call is allowed (including when no policy applies).
func (g ToolGate) evaluate(ctx context.Context, claims *auth.Claims, tool string) error {
	policy := g.policyFor(tool)
	if policy == nil {
		return nil
	}
	return policy(ctx, claims)
}

// policyFor returns the Authorizer governing tool, or nil if the call is allowed
// without a policy.
func (g ToolGate) policyFor(tool string) auth.Authorizer {
	if p, ok := g.Policies[tool]; ok {
		return p
	}
	return g.Default
}

// denial maps an Authorizer error onto a wire-safe error: only the public
// message survives, never the wrapped cause -- the SDK writes the error string
// into the JSON-RPC error returned to the client.
func denial(err error) error {
	var ae *auth.Error
	if errors.As(err, &ae) {
		return errors.New(ae.Message)
	}
	return errors.New("forbidden")
}
