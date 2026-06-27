package otel_test

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/polyglotdev/mcp-auth-go/audit"
	otelaudit "github.com/polyglotdev/mcp-auth-go/audit/otel"
)

func findCounterDataPoint(t *testing.T, rm *metricdata.ResourceMetrics, name string) metricdata.DataPoint[int64] {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %q data is %T, want Sum[int64]", name, m.Data)
			}
			if len(sum.DataPoints) == 0 {
				t.Fatalf("metric %q has no data points", name)
			}
			return sum.DataPoints[0]
		}
	}
	t.Fatalf("metric %q not found", name)
	return metricdata.DataPoint[int64]{}
}

func TestSinkMetrics(t *testing.T) {
	tests := []struct {
		name       string
		event      audit.Event
		wantMetric string
		wantLabels map[string]string // expected subset
		forbidden  []string          // attribute keys that must be absent
	}{
		{
			name:       "granted tool call",
			event:      audit.Event{Action: audit.ActionToolCall, Outcome: audit.OutcomeGranted, Tool: "read", Subject: "sub-1"},
			wantMetric: "mcp.tool.calls",
			wantLabels: map[string]string{"action": "tool_call", "outcome": "granted"},
			forbidden:  []string{"tool", "subject", "email"},
		},
		{
			name:       "rejected exchange",
			event:      audit.Event{Action: audit.ActionTokenExchange, Outcome: audit.OutcomeDenied, ReasonCode: "exchange_rejected", Audience: "aud", Email: "p@hi.test"},
			wantMetric: "mcp.broker.exchanges",
			wantLabels: map[string]string{"outcome": "denied", "reason_code": "exchange_rejected"},
			forbidden:  []string{"audience", "email"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			sink, err := otelaudit.NewSink(otelaudit.Config{MeterProvider: mp})
			if err != nil {
				t.Fatalf("NewSink: %v", err)
			}
			sink.Record(context.Background(), tt.event)

			var rm metricdata.ResourceMetrics
			if err := reader.Collect(context.Background(), &rm); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			dp := findCounterDataPoint(t, &rm, tt.wantMetric)
			for k, v := range tt.wantLabels {
				got, ok := dp.Attributes.Value(attribute.Key(k))
				if !ok || got.AsString() != v {
					t.Errorf("label %q = %q (present=%v), want %q", k, got.AsString(), ok, v)
				}
			}
			for _, bad := range tt.forbidden {
				if dp.Attributes.HasValue(attribute.Key(bad)) {
					t.Errorf("forbidden metric label %q present", bad)
				}
			}
			if dp.Value != 1 {
				t.Errorf("counter value = %d, want 1", dp.Value)
			}
		})
	}
}

func TestSinkSpanEvent(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	sink, err := otelaudit.NewSink(otelaudit.Config{})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	ctx, span := tp.Tracer("test").Start(context.Background(), "parent")
	sink.Record(ctx, audit.Event{Action: audit.ActionToolCall, Outcome: audit.OutcomeGranted, Tool: "read", Subject: "sub-1", Email: "p@hi.test"})
	span.End()

	ev := sr.Ended()[0].Events()
	if len(ev) != 1 || ev[0].Name != "mcp.tool_call" {
		t.Fatalf("events = %+v, want one named mcp.tool_call", ev)
	}
	var sawTool, sawEmail bool
	for _, a := range ev[0].Attributes {
		if string(a.Key) == "tool" {
			sawTool = true
		}
		if string(a.Key) == "email" || a.Value.AsString() == "p@hi.test" {
			sawEmail = true
		}
	}
	if !sawTool {
		t.Error("span event missing tool attribute")
	}
	if sawEmail {
		t.Error("span event leaked Email")
	}
}

func TestSinkNoActiveSpan(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	sink, err := otelaudit.NewSink(otelaudit.Config{MeterProvider: mp})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	// context.Background() carries no recording span: must not panic, metric still emitted.
	sink.Record(context.Background(), audit.Event{Action: audit.ActionToolCall, Outcome: audit.OutcomeGranted})
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if dp := findCounterDataPoint(t, &rm, "mcp.tool.calls"); dp.Value != 1 {
		t.Errorf("counter = %d, want 1", dp.Value)
	}
}
