package redisreplay_test

import (
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"

	"github.com/polyglotdev/mcp-auth-go/dpop"
	"github.com/polyglotdev/mcp-auth-go/dpop/redisreplay"
)

// ExampleFailMode_String shows the two valid failure postures and their stable
// log renderings. The zero value is intentionally invalid so the operator must
// choose availability (FailOpen) vs. strict single-use (FailClosed) consciously.
func ExampleFailMode_String() {
	fmt.Println(redisreplay.FailOpen)
	fmt.Println(redisreplay.FailClosed)
	// Output:
	// fail_open
	// fail_closed
}

// ExampleNew shows wiring the Redis-backed replay cache into a DPoP verifier.
// New validates the config but does not dial: the caller owns the client's
// connection lifecycle (pool, TLS, auth, timeouts). FailClosed trades
// availability for strict single-use -- a Redis outage rejects DPoP-bound
// requests for its duration, so pair it with alerting.
func ExampleNew() {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})

	cache, err := redisreplay.New(redisreplay.Config{
		Client:   client,
		FailMode: redisreplay.FailClosed,
	})
	if err != nil {
		log.Fatal(err)
	}

	// The distributed cache replaces the in-memory default so replay protection
	// holds across replicas sharing the same Redis.
	_ = dpop.NewVerifier(dpop.Config{ReplayCache: cache})

	fmt.Println("replay cache configured")
	// Output: replay cache configured
}
