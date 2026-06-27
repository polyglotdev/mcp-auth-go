// Package redisreplay provides a Redis-backed implementation of the core
// [github.com/polyglotdev/mcp-auth-go/dpop.ReplayCache] interface, so DPoP
// proof single-use (RFC 9449 §11.1) holds across instances behind a load
// balancer. The in-memory default ([dpop.MemoryReplayCache]) is per-process; a
// multi-replica deployment needs this shared store for cross-instance
// single-use.
//
// # Wiring
//
// The caller owns the [github.com/redis/go-redis/v9.UniversalClient] (pool,
// TLS, auth, and client-level timeouts) and passes it in. Opt in on the
// verifier with no core change:
//
//	replay, err := redisreplay.New(redisreplay.Config{
//		Client:   rdb,                  // caller-configured
//		FailMode: redisreplay.FailOpen, // see below
//		Logger:   alertingLogger,       // recommended with FailOpen
//	})
//	verifier, _ := dpop.NewVerifier(dpop.Config{ReplayCache: replay /* ... */})
//
// # Mechanism
//
// SeenBefore maps (jti, htu) to an atomic Redis SET NX with an expiry, keyed by
// KeyPrefix + base64url(sha256(jti|htu)) — a fixed-length, normalized key that
// mirrors MemoryReplayCache's keying. A set succeeds on first sight (returns
// false); an existing key is a replay (returns true). Because the check-and-set
// is atomic server-side, concurrent proofs with the same key across replicas
// resolve to exactly one first sight. The expiry is exp-now: the verifier
// passes exp = iat + IATLeeway (the freshness-window deadline), so the key's TTL
// is window-bounded and Redis evicts it automatically — no sweep is needed.
//
// # Fail mode
//
// A Redis error cannot be expressed by the bool-only interface, so FailMode is
// mandatory (its zero value is rejected by New). FailOpen returns false (allow)
// on a store error, degrading to the freshness-window-only posture (the iat gate
// still runs upstream in the verifier) — recommended, paired with alerting on
// the Warn logs. FailClosed returns true (reject), which turns a Redis outage
// into a total DPoP-auth outage (all bound traffic rejected). The error is
// always logged when a Logger is set, carrying only the error and fail_mode —
// never the jti, htu, hashed key, or any token. A nil Logger disables logging
// (no panic): the output holds no PII or secret, so silence is a valid choice,
// though discouraged with FailOpen.
//
// # Context
//
// The ReplayCache interface carries no caller context, so each call uses its own
// context.Background() bounded by OpTimeout (default 100ms); caller cancellation
// does not propagate.
package redisreplay
