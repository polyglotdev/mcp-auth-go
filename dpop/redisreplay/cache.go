package redisreplay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/polyglotdev/mcp-auth-go/dpop"
)

var _ dpop.ReplayCache = (*ReplayCache)(nil)

// FailMode selects how a store error is resolved. Its zero value is invalid so
// the operator must choose the availability-vs-strictness posture consciously.
type FailMode int

const (
	// FailOpen returns false (allow) on a store error: availability over strict
	// single-use. Protection degrades to the freshness-window-only posture (the
	// iat gate still runs upstream); pair with an alerting Logger.
	FailOpen FailMode = iota + 1
	// FailClosed returns true (reject) on a store error: strict single-use over
	// availability. A Redis outage rejects ALL DPoP-bound requests for its
	// duration -- a total auth outage, not a graceful degradation.
	FailClosed
)

// String renders the mode for logging.
func (m FailMode) String() string {
	switch m {
	case FailOpen:
		return "fail_open"
	case FailClosed:
		return "fail_closed"
	default:
		return "fail_unset"
	}
}

const (
	defaultKeyPrefix = "dpop:replay:"
	defaultOpTimeout = 100 * time.Millisecond
)

// Config wires the distributed ReplayCache. Client and FailMode are required.
type Config struct {
	// Client is the caller-owned Redis client (connection, pool, TLS, auth, and
	// client-level timeouts are the caller's concern). Required.
	Client redis.UniversalClient
	// FailMode resolves a store error. Required; the zero value is invalid.
	FailMode FailMode
	// KeyPrefix namespaces keys; empty defaults to "dpop:replay:".
	KeyPrefix string
	// Logger, when set, records one Warn per store error (error + fail_mode; never
	// key material). nil disables logging -- discouraged with FailOpen.
	Logger *slog.Logger
	// Now supplies the clock; nil defaults to time.Now (injected for tests).
	Now func() time.Time
	// OpTimeout bounds each Redis call; <= 0 defaults to 100ms. The ReplayCache
	// interface carries no caller context, so the adapter uses this as the
	// deadline.
	OpTimeout time.Duration
}

// ReplayCache is a Redis-backed dpop.ReplayCache.
type ReplayCache struct {
	client    redis.UniversalClient
	failMode  FailMode
	keyPrefix string
	logger    *slog.Logger
	now       func() time.Time
	opTimeout time.Duration
}

// New validates cfg and returns a *ReplayCache. It errors on a nil Client or an
// unset FailMode, and applies the KeyPrefix/Now/OpTimeout defaults. It does not
// dial Redis; the caller's client owns the connection lifecycle.
func New(cfg Config) (*ReplayCache, error) {
	if cfg.Client == nil {
		return nil, errors.New("redisreplay: Config.Client is required")
	}
	if cfg.FailMode != FailOpen && cfg.FailMode != FailClosed {
		return nil, errors.New("redisreplay: Config.FailMode is required (FailOpen or FailClosed)")
	}
	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = defaultKeyPrefix
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	opTimeout := cfg.OpTimeout
	if opTimeout <= 0 {
		opTimeout = defaultOpTimeout
	}
	return &ReplayCache{
		client:    cfg.Client,
		failMode:  cfg.FailMode,
		keyPrefix: keyPrefix,
		logger:    cfg.Logger,
		now:       now,
		opTimeout: opTimeout,
	}, nil
}

// SeenBefore atomically records (jti, htu) and reports whether that pair was
// already present and unexpired (a replay), via SET <key> NX with an expiry of
// exp-now. A store error is resolved by the FailMode (checked before the
// set-result, so a transient error never reads as a replay) and logged without
// any key material. htu arrives already query/fragment-stripped from checkProof.
func (c *ReplayCache) SeenBefore(jti, htu string, exp time.Time) bool {
	ttl := exp.Sub(c.now())
	if ttl < time.Millisecond { // includes ttl <= 0; avoids a spurious PX 0 error
		return false
	}
	sum := sha256.Sum256([]byte(jti + "|" + htu))
	key := c.keyPrefix + base64.RawURLEncoding.EncodeToString(sum[:])

	ctx, cancel := context.WithTimeout(context.Background(), c.opTimeout)
	defer cancel()

	set, err := c.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil { // error FIRST -- never interpret the bool on error
		if c.logger != nil {
			c.logger.Warn("dpop replay store error",
				slog.Any("err", err), slog.String("fail_mode", c.failMode.String()))
		}
		return c.failMode == FailClosed
	}
	return !set // set => first sight => false; not set => existed => replay => true
}
