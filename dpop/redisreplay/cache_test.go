package redisreplay_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/polyglotdev/mcp-auth-go/dpop/redisreplay"
)

func TestNewValidation(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	tests := []struct {
		name    string
		cfg     redisreplay.Config
		wantErr bool
	}{
		{name: "nil client", cfg: redisreplay.Config{FailMode: redisreplay.FailOpen}, wantErr: true},
		{name: "unset fail mode", cfg: redisreplay.Config{Client: client}, wantErr: true},
		{name: "valid fail open", cfg: redisreplay.Config{Client: client, FailMode: redisreplay.FailOpen}, wantErr: false},
		{name: "valid fail closed", cfg: redisreplay.Config{Client: client, FailMode: redisreplay.FailClosed}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := redisreplay.New(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && c == nil {
				t.Fatal("New returned nil cache without error")
			}
		})
	}
}

func newCache(t *testing.T, fm redisreplay.FailMode, logger *slog.Logger) (*redisreplay.ReplayCache, *miniredis.Miniredis, time.Time) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	now := time.Unix(1_000_000, 0)
	c, err := redisreplay.New(redisreplay.Config{
		Client:    redis.NewClient(&redis.Options{Addr: mr.Addr()}),
		FailMode:  fm,
		Logger:    logger,
		Now:       func() time.Time { return now },
		OpTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, mr, now
}

// TestSeenBeforeLifecycle is a focused sequential scenario: first-sight, the
// deterministic TTL, replay, distinct keys, and TTL expiry on one cache.
func TestSeenBeforeLifecycle(t *testing.T) {
	c, mr, now := newCache(t, redisreplay.FailOpen, nil)
	exp := now.Add(30 * time.Second)
	if c.SeenBefore("jti1", "https://h/x", exp) {
		t.Fatal("first sight must be false")
	}
	// Deterministic TTL (spec criterion (a)/M7): the stored expiry == exp - Now.
	sum := sha256.Sum256([]byte("jti1" + "|" + "https://h/x"))
	key := "dpop:replay:" + base64.RawURLEncoding.EncodeToString(sum[:])
	if ttl := mr.TTL(key); ttl < 29*time.Second || ttl > 30*time.Second {
		t.Fatalf("stored TTL = %v, want ~30s (exp-Now)", ttl)
	}
	if !c.SeenBefore("jti1", "https://h/x", exp) {
		t.Fatal("replay must be true")
	}
	if c.SeenBefore("jti2", "https://h/x", exp) {
		t.Fatal("distinct jti must be false")
	}
	if c.SeenBefore("jti1", "https://h/y", exp) {
		t.Fatal("distinct htu must be false")
	}
	mr.FastForward(31 * time.Second) // age the ~30s key past expiry
	if c.SeenBefore("jti1", "https://h/x", exp) {
		t.Fatal("after expiry must be first-sight (false) again")
	}
}

func TestSeenBeforeTTLGuard(t *testing.T) {
	tests := []struct {
		name   string
		offset time.Duration // exp - now
	}{
		{name: "negative ttl", offset: -time.Second},
		{name: "zero ttl", offset: 0},
		{name: "sub-millisecond ttl", offset: 500 * time.Microsecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, mr, now := newCache(t, redisreplay.FailOpen, nil)
			if c.SeenBefore("jti", "https://h/x", now.Add(tt.offset)) {
				t.Fatal("ttl guard must return false")
			}
			if keys := mr.Keys(); len(keys) != 0 {
				t.Fatalf("guard must write no key, got %v", keys)
			}
		})
	}
}

func TestSeenBeforeFailModeOnStoreError(t *testing.T) {
	tests := []struct {
		name string
		mode redisreplay.FailMode
		want bool
	}{
		{name: "fail open allows", mode: redisreplay.FailOpen, want: false},
		{name: "fail closed rejects", mode: redisreplay.FailClosed, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, mr, now := newCache(t, tt.mode, nil)
			mr.Close() // real go-redis connection error => fail-mode path
			if got := c.SeenBefore("jti", "https://h/x", now.Add(30*time.Second)); got != tt.want {
				t.Fatalf("SeenBefore = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNoKeyMaterialInLog(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	c, mr, now := newCache(t, redisreplay.FailOpen, logger)
	mr.Close()
	const jti, htu = "SECRET-JTI-abc123", "https://internal.example/SECRET-PATH"
	c.SeenBefore(jti, htu, now.Add(30*time.Second))
	sum := sha256.Sum256([]byte(jti + "|" + htu))
	key := base64.RawURLEncoding.EncodeToString(sum[:])
	out := buf.String()
	if !strings.Contains(out, "fail_mode=fail_open") {
		t.Fatalf("expected a Warn with fail_mode, got %q", out)
	}
	for _, secret := range []string{jti, htu, key} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaked %q in %q", secret, out)
		}
	}
}

func TestSeenBeforeConcurrentSingleUse(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	now := time.Unix(1_000_000, 0)
	const n = 16
	caches := make([]*redisreplay.ReplayCache, n)
	for i := range caches {
		caches[i], err = redisreplay.New(redisreplay.Config{
			Client:    redis.NewClient(&redis.Options{Addr: mr.Addr()}),
			FailMode:  redisreplay.FailClosed,
			Now:       func() time.Time { return now },
			OpTimeout: time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	exp := now.Add(30 * time.Second)
	var wg sync.WaitGroup
	var mu sync.Mutex
	firstSights := 0
	for i := range caches {
		wg.Add(1)
		go func(c *redisreplay.ReplayCache) {
			defer wg.Done()
			if !c.SeenBefore("jti", "https://h/x", exp) {
				mu.Lock()
				firstSights++
				mu.Unlock()
			}
		}(caches[i])
	}
	wg.Wait()
	if firstSights != 1 {
		t.Fatalf("exactly one instance must see first-sight, got %d", firstSights)
	}
}

// stubClient overrides only SetNX to inject errors/timeouts; un-overridden
// methods are never called.
type stubClient struct {
	redis.UniversalClient
	block bool
	err   error
	set   bool
}

func (s stubClient) SetNX(ctx context.Context, key string, value any, _ time.Duration) *redis.BoolCmd {
	if s.block {
		<-ctx.Done()
	}
	cmd := redis.NewBoolCmd(ctx, "set", key, value, "nx")
	switch {
	case s.block:
		cmd.SetErr(ctx.Err())
	case s.err != nil:
		cmd.SetErr(s.err)
	default:
		cmd.SetVal(s.set)
	}
	return cmd
}

func TestSeenBeforeStubErrorPaths(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	exp := now.Add(30 * time.Second)
	mk := func(c redis.UniversalClient, fm redisreplay.FailMode, op time.Duration) *redisreplay.ReplayCache {
		rc, err := redisreplay.New(redisreplay.Config{Client: c, FailMode: fm, Now: func() time.Time { return now }, OpTimeout: op})
		if err != nil {
			t.Fatal(err)
		}
		return rc
	}
	tests := []struct {
		name   string
		client redis.UniversalClient
		mode   redisreplay.FailMode
		op     time.Duration
		want   bool
	}{
		{name: "error-first fail open", client: stubClient{set: false, err: errors.New("proto boom")}, mode: redisreplay.FailOpen, op: time.Second, want: false},
		{name: "error-first fail closed", client: stubClient{set: false, err: errors.New("proto boom")}, mode: redisreplay.FailClosed, op: time.Second, want: true},
		{name: "op timeout fail closed", client: stubClient{block: true}, mode: redisreplay.FailClosed, op: 10 * time.Millisecond, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mk(tt.client, tt.mode, tt.op).SeenBefore("j", "h", exp); got != tt.want {
				t.Fatalf("SeenBefore = %v, want %v", got, tt.want)
			}
		})
	}
}
