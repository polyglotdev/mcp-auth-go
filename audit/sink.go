package audit

import (
	"context"
	"log/slog"
)

// Sink records an audit Event. Record returns no error: emission is best-effort
// and the implementation owns durability, buffering, retry, and its own error
// handling. Record must not block indefinitely and must not panic. The library
// calls Record synchronously at the decision point.
type Sink interface {
	Record(ctx context.Context, e Event)
}

type slogSink struct{ logger *slog.Logger }

// NewSlogSink returns the default compliance Sink: it logs the full Event
// (including Subject and Email) at Info level under the "audit" message. Because
// the record carries PII, point logger at BAA-covered storage. A nil logger is a
// programming error and panics at construction (mirroring transport/http's
// nil-logger guard) rather than silently logging PII to the process default.
func NewSlogSink(logger *slog.Logger) Sink {
	if logger == nil {
		// Construction-time guard, not a request path: fail loud rather than
		// silently default a PII-carrying compliance sink to the global logger.
		panic("audit: NewSlogSink requires a non-nil logger")
	}
	return slogSink{logger: logger}
}

// Record logs every Event field. It holds no token, so nothing secret is logged;
// Email is PII and assumes the logger targets BAA-covered storage.
func (s slogSink) Record(ctx context.Context, e Event) {
	s.logger.LogAttrs(ctx, slog.LevelInfo, "audit",
		slog.String("action", string(e.Action)),
		slog.String("outcome", string(e.Outcome)),
		slog.String("reason_code", e.ReasonCode),
		slog.String("tool", e.Tool),
		slog.String("subject", e.Subject),
		slog.String("issuer", e.Issuer),
		slog.String("audience", e.Audience),
		slog.Any("scopes", e.Scopes),
		slog.String("email", e.Email),
		slog.Time("time", e.Time),
	)
}

type nopSink struct{}

// NewNopSink returns a Sink that records nothing -- the explicit opt-out.
func NewNopSink() Sink { return nopSink{} }

func (nopSink) Record(context.Context, Event) {}

type multiSink []Sink

// NewMultiSink returns a Sink that fans an Event out to each sink in order,
// skipping nil elements. It does not recover a panicking sink (a panic is a bug
// to surface), so place the durable compliance sink first: a panic in an earlier
// sink prevents later sinks from recording.
func NewMultiSink(sinks ...Sink) Sink {
	nonNil := make([]Sink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			nonNil = append(nonNil, s)
		}
	}
	return multiSink(nonNil)
}

func (m multiSink) Record(ctx context.Context, e Event) {
	for _, s := range m {
		s.Record(ctx, e)
	}
}
