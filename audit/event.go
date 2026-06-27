// Package audit is a transport-agnostic security-audit seam: a typed Event
// recorded at access decisions (tool authorization, token exchange) and handed
// to a pluggable Sink. The Event partitions its fields by sensitivity so a
// telemetry sink can never emit PII or an unbounded/attacker-controlled metric
// label; see MetricLabels and TraceAttributes.
package audit

import (
	"strings"
	"time"
)

// Action is the kind of security decision an Event records.
type Action string

const (
	// ActionToolCall is a per-tool authorization decision at the MCP gate.
	ActionToolCall Action = "tool_call"
	// ActionTokenExchange is an RFC 8693 delegated-credential issuance.
	ActionTokenExchange Action = "token_exchange"
)

// Outcome is the result of a decision.
type Outcome string

const (
	// OutcomeGranted is an allowed call or an issued credential.
	OutcomeGranted Outcome = "granted"
	// OutcomeDenied is a policy denial or an authorization-server rejection.
	OutcomeDenied Outcome = "denied"
	// OutcomeError is an operational failure (e.g. the AS was unreachable).
	OutcomeError Outcome = "error"
)

// Attr is one key/value attribute, neutral across metrics and traces.
type Attr struct{ Key, Value string }

// Event is one audited security decision. Its fields are partitioned into three
// tiers (see MetricLabels and TraceAttributes); construct it at an emission
// point and hand it to a Sink.
type Event struct {
	// Tier 1 -- bounded and not client-controlled: safe as metric labels.
	Action     Action
	Outcome    Outcome
	ReasonCode string // stable Code on denied/error; "" on granted; never Cause text

	// Tier 2 -- span attributes only (never metric labels): client-controlled or
	// high-cardinality, but PHI-safe.
	Tool     string
	Subject  string
	Issuer   string
	Audience string
	Scopes   []string

	// Tier 3 -- PII: compliance/BAA sinks only; never a telemetry attribute.
	Email string

	// Time is the decision time, recorded so an async sink's write time is not
	// mistaken for it. It is not an attribute/label (OTel timestamps natively).
	Time time.Time
}

// MetricLabels returns the tier-1 attributes (action, outcome, and reason_code
// when set) that are safe as metric label values: each is a bounded constant,
// not a client-controlled or high-cardinality identifier. Tool, Subject,
// Audience, Scopes, and Email are deliberately excluded.
func (e Event) MetricLabels() []Attr {
	attrs := []Attr{
		{Key: "action", Value: string(e.Action)},
		{Key: "outcome", Value: string(e.Outcome)},
	}
	if e.ReasonCode != "" {
		attrs = append(attrs, Attr{Key: "reason_code", Value: e.ReasonCode})
	}
	return attrs
}

// TraceAttributes returns the tier-1 labels plus the PHI-safe tier-2 fields
// (tool, subject, issuer, audience, and space-joined scopes) for a span event.
// Email is never included. Empty fields are omitted.
func (e Event) TraceAttributes() []Attr {
	attrs := e.MetricLabels()
	if e.Tool != "" {
		attrs = append(attrs, Attr{Key: "tool", Value: e.Tool})
	}
	if e.Subject != "" {
		attrs = append(attrs, Attr{Key: "subject", Value: e.Subject})
	}
	if e.Issuer != "" {
		attrs = append(attrs, Attr{Key: "issuer", Value: e.Issuer})
	}
	if e.Audience != "" {
		attrs = append(attrs, Attr{Key: "audience", Value: e.Audience})
	}
	if len(e.Scopes) > 0 {
		attrs = append(attrs, Attr{Key: "scopes", Value: strings.Join(e.Scopes, " ")})
	}
	return attrs
}
