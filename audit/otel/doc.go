// Package otel adapts the core audit.Sink to OpenTelemetry: each audit.Event
// becomes an Int64 counter increment (bounded labels from Event.MetricLabels)
// and, when a recording span is active, a span event (PHI-safe attributes from
// Event.TraceAttributes, never Email). It depends on the OpenTelemetry API only
// -- the consumer wires the SDK and providers; the OTel SDK is a test-only
// dependency here, so importing this package keeps it out of a consumer's graph
// unless they already use OpenTelemetry.
//
// Import it under an alias to avoid colliding with go.opentelemetry.io/otel:
//
//	import otelaudit "github.com/polyglotdev/mcp-auth-go/audit/otel"
package otel
