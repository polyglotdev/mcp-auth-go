package dpop

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// NonceSource issues and validates resource-server DPoP nonces (RFC 9449 §9).
// The default implementation is SignedNonce (stateless). Implementations MUST
// be safe for concurrent use. A nonce is opaque to the client (§8.9) and
// unpredictable (§8.3); it is time-window valid, NOT single-use (§11.1), so it
// complements -- never replaces -- the jti ReplayCache.
type NonceSource interface {
	// Issue mints a fresh nonce stamped at now.
	Issue(now time.Time) string
	// Validate reports whether nonce is one this source issued and is still
	// within its lifetime at now.
	Validate(nonce string, now time.Time) bool
}

const (
	nonceTSLen     = 8                          // big-endian Unix seconds
	nonceRandLen   = 16                         // crypto/rand entropy
	noncePayload   = nonceTSLen + nonceRandLen  // the HMAC'd prefix (24 bytes)
	nonceLen       = noncePayload + sha256.Size // full nonce (56 bytes)
	nonceMinSecret = 32                         // HMAC-SHA256 key floor (256-bit)
	nonceDefaultTL = 5 * time.Minute            // lifetime fallback
	nonceFutureTL  = 5 * time.Second            // forward-skew tolerance; must stay << lifetime
)

// SignedNonce is the stateless NonceSource: each nonce is
// base64url( ts8 ‖ rand16 ‖ HMAC-SHA256(secret, ts8‖rand16) ). A valid MAC
// proves this server minted it, so the embedded timestamp is trustworthy with
// no server-side state; any instance sharing the secret can validate it (no
// shared store needed for a multi-replica deployment).
type SignedNonce struct {
	secret   []byte
	lifetime time.Duration
}

// NewSignedNonce builds a SignedNonce. secret MUST be at least 32 bytes (the
// HMAC-SHA256 key floor); a shorter secret is an error. lifetime <= 0 falls
// back to 5 minutes. The secret is copied so a later mutation by the caller
// cannot change validation.
func NewSignedNonce(secret []byte, lifetime time.Duration) (*SignedNonce, error) {
	if len(secret) < nonceMinSecret {
		return nil, fmt.Errorf("dpop: nonce secret must be at least %d bytes, got %d", nonceMinSecret, len(secret))
	}
	if lifetime <= 0 {
		lifetime = nonceDefaultTL
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &SignedNonce{secret: cp, lifetime: lifetime}, nil
}

// mac computes HMAC-SHA256(secret, payload).
func (s *SignedNonce) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, s.secret)
	h.Write(payload)
	return h.Sum(nil)
}

// Issue implements NonceSource. It returns "" only if crypto/rand fails (a
// documented, near-impossible degradation the transport treats as "no nonce" --
// never a predictable value).
func (s *SignedNonce) Issue(now time.Time) string {
	sec := now.Unix()
	if sec < 0 {
		return "" // pre-1970 clock: refuse rather than emit a wrapped timestamp
	}
	buf := make([]byte, nonceLen)
	binary.BigEndian.PutUint64(buf[:nonceTSLen], uint64(sec))
	if _, err := rand.Read(buf[nonceTSLen:noncePayload]); err != nil {
		return ""
	}
	copy(buf[noncePayload:], s.mac(buf[:noncePayload]))
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Validate implements NonceSource. It fails closed on any decode, length, MAC,
// freshness, or forward-skew failure. The acceptance window is
// [now-lifetime, now+nonceFutureTL].
func (s *SignedNonce) Validate(nonce string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != nonceLen {
		return false
	}
	payload, mac := raw[:noncePayload], raw[noncePayload:]
	if !hmac.Equal(mac, s.mac(payload)) {
		return false
	}
	ts := binary.BigEndian.Uint64(payload[:nonceTSLen])
	if ts > math.MaxInt64 {
		return false // outside the range Issue ever produces
	}
	issued := time.Unix(int64(ts), 0)
	if now.Sub(issued) > s.lifetime {
		return false // stale
	}
	return !issued.After(now.Add(nonceFutureTL)) // reject implausibly future
}

// IssueNonce mints a nonce for the transport's challenge and rotation, or ""
// if no NonceSource is configured.
func (v *Verifier) IssueNonce(now time.Time) string {
	if v.nonce == nil {
		return ""
	}
	return v.nonce.Issue(now)
}

// NonceConfigured reports whether a NonceSource is set. The mcpauth transport
// uses it to refuse (panic at construction) a config it cannot honor.
func (v *Verifier) NonceConfigured() bool { return v.nonce != nil }
