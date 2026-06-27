//go:build integration

package redisreplay_test

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/polyglotdev/mcp-auth-go/dpop/redisreplay"
)

// TestIntegrationRealRedis re-proves first-sight/replay and real server-side TTL
// expiry against a real Redis container. Build-tagged so it is excluded from the
// default test run (make check stays Docker-free). Run with:
//
//	go test -tags=integration -run TestIntegration ./dpop/redisreplay/
func TestIntegrationRealRedis(t *testing.T) {
	ctx := context.Background()
	rc, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Fatalf("start redis container: %v", err)
	}
	t.Cleanup(func() { _ = rc.Terminate(ctx) })

	url, err := rc.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_000_000, 0)
	c, err := redisreplay.New(redisreplay.Config{
		Client:    redis.NewClient(opts),
		FailMode:  redisreplay.FailClosed,
		Now:       func() time.Time { return now },
		OpTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	exp := now.Add(2 * time.Second)
	if c.SeenBefore("jti", "https://h/x", exp) {
		t.Fatal("first sight must be false")
	}
	if !c.SeenBefore("jti", "https://h/x", exp) {
		t.Fatal("replay must be true")
	}
	// Real server-side TTL expiry (no FastForward): the ~2s key TTL elapses.
	time.Sleep(2500 * time.Millisecond)
	if c.SeenBefore("jti", "https://h/x", exp) {
		t.Fatal("after real TTL expiry must be first-sight (false) again")
	}
}
