package audit_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/polyglotdev/mcp-auth-go/audit"
)

// capture is a fake Sink that records events (reused across the suite).
type capture struct{ events []audit.Event }

func (c *capture) Record(_ context.Context, e audit.Event) { c.events = append(c.events, e) }

func TestNewSlogSinkNilLoggerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewSlogSink(nil) must panic")
		}
	}()
	_ = audit.NewSlogSink(nil)
}

func TestSlogSinkLogsAllFields(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	sink := audit.NewSlogSink(logger)
	sink.Record(context.Background(), audit.Event{
		Action: audit.ActionToolCall, Outcome: audit.OutcomeGranted,
		Tool: "read_record", Subject: "sub-1", Email: "p@hi.test",
	})
	out := buf.String()
	for _, want := range []string{"action=tool_call", "outcome=granted", "tool=read_record", "subject=sub-1", "email=p@hi.test"} {
		if !strings.Contains(out, want) {
			t.Errorf("slog output missing %q in %q", want, out)
		}
	}
}

func TestMultiSinkFansOutAndSkipsNil(t *testing.T) {
	a, b := &capture{}, &capture{}
	sink := audit.NewMultiSink(a, nil, b) // nil element must be skipped, not panic
	sink.Record(context.Background(), audit.Event{Action: audit.ActionToolCall, Outcome: audit.OutcomeDenied})
	if len(a.events) != 1 || len(b.events) != 1 {
		t.Fatalf("fan-out failed: a=%d b=%d", len(a.events), len(b.events))
	}
}

func TestNopSinkRecordsNothing(_ *testing.T) {
	audit.NewNopSink().Record(context.Background(), audit.Event{}) // must not panic
}
