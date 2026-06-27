package dpop

import (
	"encoding/base64"
	"testing"
	"time"
)

// testNonceSecret is a 32-byte secret shared by the nonce-related tables.
func testNonceSecret() []byte { return []byte("0123456789abcdef0123456789abcdef") }

// TestSignedNonceValidate is a table over every accept/reject path of
// SignedNonce.Validate. Rows are pure data; the nonce variants (fresh,
// tampered, wrong-secret) are precomputed as locals before the table.
func TestSignedNonceValidate(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	ns, err := NewSignedNonce(testNonceSecret(), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	other, err := NewSignedNonce([]byte("FEDCBA9876543210FEDCBA9876543210"), time.Minute)
	if err != nil {
		t.Fatalf("NewSignedNonce(other): %v", err)
	}

	fresh := ns.Issue(now)
	raw, err := base64.RawURLEncoding.DecodeString(fresh)
	if err != nil {
		t.Fatalf("decode fresh nonce: %v", err)
	}
	raw[0] ^= 0xFF // corrupt the timestamp region -> MAC mismatch
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	tests := []struct {
		name  string
		nonce string
		at    time.Time
		want  bool
	}{
		{name: "fresh", nonce: fresh, at: now, want: true},
		{name: "within lifetime", nonce: fresh, at: now.Add(59 * time.Second), want: true},
		{name: "stale past lifetime", nonce: fresh, at: now.Add(61 * time.Second), want: false},
		{name: "implausibly future", nonce: fresh, at: now.Add(-time.Hour), want: false},
		{name: "tampered byte", nonce: tampered, at: now, want: false},
		{name: "wrong secret", nonce: other.Issue(now), at: now, want: false},
		{name: "wrong length", nonce: "aGVsbG8", at: now, want: false},
		{name: "not base64url", nonce: "not a valid nonce !!", at: now, want: false},
		{name: "empty", nonce: "", at: now, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ns.Validate(tt.nonce, tt.at); got != tt.want {
				t.Errorf("Validate(%q) at %v = %v, want %v", tt.nonce, tt.at, got, tt.want)
			}
		})
	}
}

// TestNewSignedNonceSecretFloor tables the >=32-byte secret requirement.
func TestNewSignedNonceSecretFloor(t *testing.T) {
	tests := []struct {
		name    string
		secret  []byte
		wantErr bool
	}{
		{name: "32-byte secret ok", secret: make([]byte, 32), wantErr: false},
		{name: "64-byte secret ok", secret: make([]byte, 64), wantErr: false},
		{name: "31-byte secret rejected", secret: make([]byte, 31), wantErr: true},
		{name: "empty secret rejected", secret: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSignedNonce(tt.secret, time.Minute)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSignedNonce(%d-byte secret) err = %v, wantErr %v", len(tt.secret), err, tt.wantErr)
			}
		})
	}
}

// TestSignedNonceLifetimeDefault proves lifetime <= 0 falls back to 5 minutes.
func TestSignedNonceLifetimeDefault(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	ns, err := NewSignedNonce(testNonceSecret(), 0) // 0 => 5m default
	if err != nil {
		t.Fatalf("NewSignedNonce: %v", err)
	}
	nonce := ns.Issue(now)

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{name: "within default 5m", at: now.Add(4 * time.Minute), want: true},
		{name: "past default 5m", at: now.Add(6 * time.Minute), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ns.Validate(nonce, tt.at); got != tt.want {
				t.Errorf("Validate at %v = %v, want %v", tt.at, got, tt.want)
			}
		})
	}
}
