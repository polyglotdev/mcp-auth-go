package audit_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/polyglotdev/mcp-auth-go/audit"
)

// ExampleEvent_MetricLabels shows the tier-1 attributes that are safe as metric
// label values: each is a bounded constant, never a client-controlled or
// high-cardinality identifier. Tool, Subject, Email, and Scopes are excluded,
// and reason_code appears only when set.
func ExampleEvent_MetricLabels() {
	e := audit.Event{
		Action:     audit.ActionToolCall,
		Outcome:    audit.OutcomeDenied,
		ReasonCode: "insufficient_scope",
		Tool:       "read_record",    // excluded: client-controlled
		Subject:    "user-123",       // excluded: high cardinality
		Email:      "p@example.test", // excluded: PII
	}
	for _, a := range e.MetricLabels() {
		fmt.Printf("%s=%s\n", a.Key, a.Value)
	}
	// Output:
	// action=tool_call
	// outcome=denied
	// reason_code=insufficient_scope
}

// ExampleEvent_TraceAttributes shows the richer span-attribute set: the tier-1
// labels plus the PHI-safe tier-2 fields (tool, subject, issuer, audience, and
// space-joined scopes). Email is never included, and empty fields are omitted --
// here a granted outcome carries no reason_code.
func ExampleEvent_TraceAttributes() {
	e := audit.Event{
		Action:   audit.ActionToolCall,
		Outcome:  audit.OutcomeGranted,
		Tool:     "read_record",
		Subject:  "user-123",
		Issuer:   "https://acme.okta.com",
		Audience: "https://mcp.internal.acme.com",
		Scopes:   []string{"mcp:read", "mcp:write"},
		Email:    "p@example.test", // never emitted as a span attribute
	}
	for _, a := range e.TraceAttributes() {
		fmt.Printf("%s=%s\n", a.Key, a.Value)
	}
	// Output:
	// action=tool_call
	// outcome=granted
	// tool=read_record
	// subject=user-123
	// issuer=https://acme.okta.com
	// audience=https://mcp.internal.acme.com
	// scopes=mcp:read mcp:write
}

// printSink is a tiny audit.Sink for the fan-out example; real sinks write to
// logs (NewSlogSink), metrics, or traces (audit/otel).
type printSink struct{ name string }

func (p printSink) Record(_ context.Context, e audit.Event) {
	fmt.Printf("%s recorded %s/%s\n", p.name, e.Action, e.Outcome)
}

// ExampleNewMultiSink shows fanning one Event out to several sinks in order.
// A nil element is skipped rather than panicking, so an optional sink can be
// wired in conditionally. Place the durable compliance sink first.
func ExampleNewMultiSink() {
	sink := audit.NewMultiSink(printSink{name: "compliance"}, nil, printSink{name: "metrics"})

	sink.Record(context.Background(), audit.Event{
		Action:  audit.ActionToolCall,
		Outcome: audit.OutcomeGranted,
	})
	// Output:
	// compliance recorded tool_call/granted
	// metrics recorded tool_call/granted
}

// ExampleNewSlogSink shows wiring the default compliance sink. The record
// carries Subject and Email (PII), so point the logger at BAA-covered storage.
// A nil logger is a programming error and panics at construction.
func ExampleNewSlogSink() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	sink := audit.NewSlogSink(logger)

	// Record is called synchronously at the decision point.
	sink.Record(context.Background(), audit.Event{
		Action:  audit.ActionTokenExchange,
		Outcome: audit.OutcomeGranted,
		Subject: "user-123",
	})
}
