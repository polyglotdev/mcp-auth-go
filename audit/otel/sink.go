package otel

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/polyglotdev/mcp-auth-go/audit"
)

const scopeName = "github.com/polyglotdev/mcp-auth-go/audit/otel"

// Config wires the OTel providers. MeterProvider is optional and defaults to the
// global provider. No TracerProvider is needed: span events attach to the
// caller's active span (trace.SpanFromContext).
type Config struct {
	MeterProvider metric.MeterProvider
}

type sink struct {
	toolCalls metric.Int64Counter
	exchanges metric.Int64Counter
}

// NewSink builds an OTel audit.Sink. It creates the two counters once; a
// counter-creation error (e.g. a bad instrument name) is returned.
func NewSink(cfg Config) (audit.Sink, error) {
	mp := cfg.MeterProvider
	if mp == nil {
		mp = otel.GetMeterProvider()
	}
	meter := mp.Meter(scopeName)
	toolCalls, err := meter.Int64Counter("mcp.tool.calls")
	if err != nil {
		return nil, err
	}
	exchanges, err := meter.Int64Counter("mcp.broker.exchanges")
	if err != nil {
		return nil, err
	}
	return &sink{toolCalls: toolCalls, exchanges: exchanges}, nil
}

// Record increments the per-action counter with bounded labels and, when a
// recording span is active, adds a span event with PHI-safe attributes.
func (s *sink) Record(ctx context.Context, e audit.Event) {
	counter := s.exchanges
	if e.Action == audit.ActionToolCall {
		counter = s.toolCalls
	}
	counter.Add(ctx, 1, metric.WithAttributes(toKV(e.MetricLabels())...))

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("mcp."+string(e.Action), trace.WithAttributes(toKV(e.TraceAttributes())...))
	}
}

// toKV maps the core audit attributes onto OTel string key/values.
func toKV(attrs []audit.Attr) []attribute.KeyValue {
	kvs := make([]attribute.KeyValue, len(attrs))
	for i, a := range attrs {
		kvs[i] = attribute.String(a.Key, a.Value)
	}
	return kvs
}
