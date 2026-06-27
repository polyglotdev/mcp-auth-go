package otel_test

import (
	"fmt"
	"log"

	"github.com/polyglotdev/mcp-auth-go/audit/otel"
)

// ExampleNewSink shows wiring the OpenTelemetry audit sink. An empty Config uses
// the global MeterProvider; set Config.MeterProvider to target a specific one.
// No TracerProvider is needed -- span events attach to the caller's active span.
// The result is an audit.Sink: hand it to the core directly, or compose it with
// a compliance sink via audit.NewMultiSink.
func ExampleNewSink() {
	sink, err := otel.NewSink(otel.Config{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("otel audit sink ready:", sink != nil)
	// Output: otel audit sink ready: true
}
