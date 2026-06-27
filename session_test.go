package auth

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

// newDeterministicIDs returns a session-ID generator that yields sess-1,
// sess-2, ... so tests can assert on exact IDs without random churn.
func newDeterministicIDs() func() string {
	var counter int
	return func() string {
		counter++
		return "sess-" + strconv.Itoa(counter)
	}
}

// TestMemorySessionOpenAndCount verifies a freshly opened session is counted
// for its owner and not leaked into another user's count.
func TestMemorySessionOpenAndCount(t *testing.T) {
	store := NewMemorySessionStore(SessionConfig{
		Timeout:              time.Hour,
		MaxConcurrentPerUser: 5,
	}, newDeterministicIDs())

	now := time.Now()
	id, err := store.Open("alice", now)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if id != "sess-1" {
		t.Errorf("id = %q, want sess-1", id)
	}
	if n := store.Count("alice", now); n != 1 {
		t.Errorf("Count = %d, want 1", n)
	}
	if n := store.Count("bob", now); n != 0 {
		t.Errorf("Count(bob) = %d, want 0 (per-user isolation)", n)
	}
}

// TestMemorySessionConcurrencyCap proves the per-user cap rejects the
// over-limit Open while leaving other users unaffected.
func TestMemorySessionConcurrencyCap(t *testing.T) {
	store := NewMemorySessionStore(SessionConfig{
		Timeout:              time.Hour,
		MaxConcurrentPerUser: 3,
	}, newDeterministicIDs())

	now := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := store.Open("alice", now); err != nil {
			t.Fatalf("Open #%d: %v", i, err)
		}
	}

	_, err := store.Open("alice", now)
	if !errors.Is(err, ErrSessionLimitExceeded) {
		t.Errorf("4th Open err = %v, want ErrSessionLimitExceeded", err)
	}

	// A different user must not be affected.
	if _, err := store.Open("bob", now); err != nil {
		t.Errorf("Open(bob) blocked by alice's cap: %v", err)
	}
}

// TestMemorySessionSlidingTimeout proves Touch within the window keeps a
// session alive and that an expired session is reaped so its slot is reusable
// and its ID can no longer be touched.
func TestMemorySessionSlidingTimeout(t *testing.T) {
	store := NewMemorySessionStore(SessionConfig{
		Timeout:              5 * time.Minute,
		MaxConcurrentPerUser: 1, // cap of 1 lets us prove expiry frees a slot
	}, newDeterministicIDs())

	t0 := time.Now()
	id, err := store.Open("alice", t0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Touch within the window keeps the session alive.
	if err := store.Touch(id, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("Touch within window: %v", err)
	}

	// After timeout, opening a new one must succeed (the old one is reaped).
	idNew, err := store.Open("alice", t0.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("Open after timeout: %v", err)
	}
	if idNew == id {
		t.Errorf("new session id collided with reaped id")
	}

	// The old session's Touch must now report invalid.
	if err := store.Touch(id, t0.Add(20*time.Minute)); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("Touch on reaped session: %v, want ErrInvalidSession", err)
	}
}

// TestMemorySessionCloseFreesSlot proves Close immediately frees the slot
// under the per-user cap, even without waiting for timeout.
func TestMemorySessionCloseFreesSlot(t *testing.T) {
	store := NewMemorySessionStore(SessionConfig{
		Timeout:              time.Hour,
		MaxConcurrentPerUser: 1,
	}, newDeterministicIDs())

	now := time.Now()
	id, err := store.Open("alice", now)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	store.Close(id)

	if _, err := store.Open("alice", now); err != nil {
		t.Errorf("Open after Close should succeed: %v", err)
	}
}

// TestMemorySessionRejectsEmptyUser proves Open rejects an empty userID rather
// than silently bucketing anonymous sessions together.
func TestMemorySessionRejectsEmptyUser(t *testing.T) {
	store := NewMemorySessionStore(SessionConfig{Timeout: time.Hour, MaxConcurrentPerUser: 1}, newDeterministicIDs())
	if _, err := store.Open("", time.Now()); err == nil {
		t.Error("Open with empty userID should error")
	}
}

// TestRandomSessionIDIsUnique exercises randomSessionID across a 1024 sample
// to catch a regression that would shrink entropy or reuse IDs.
func TestRandomSessionIDIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1024)
	for i := 0; i < 1024; i++ {
		id := randomSessionID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate session id at iter %d: %s", i, id)
		}
		seen[id] = struct{}{}
		if len(id) != 32 { // 16 bytes hex
			t.Fatalf("id length = %d, want 32", len(id))
		}
	}
}

// TestMemorySessionPerUserIsolation verifies the test fails loudly if Open's
// userID-isolation breaks -- a regression guard for the userID==userID check
// inside countForUserLocked.
func TestMemorySessionPerUserIsolation(t *testing.T) {
	store := NewMemorySessionStore(SessionConfig{
		Timeout:              time.Hour,
		MaxConcurrentPerUser: 2,
	}, newDeterministicIDs())

	now := time.Now()
	users := []string{"alice", "bob", "carol"}
	for _, u := range users {
		for i := 0; i < 2; i++ {
			if _, err := store.Open(u, now); err != nil {
				t.Fatalf("Open(%s) #%d: %v", u, i, err)
			}
		}
	}
	for _, u := range users {
		if n := store.Count(u, now); n != 2 {
			t.Errorf("Count(%s) = %d, want 2 (cap not affecting other users)", u, n)
		}
	}
	for _, u := range users {
		if _, err := store.Open(u, now); !errors.Is(err, ErrSessionLimitExceeded) {
			t.Errorf("Open(%s) #3: err = %v, want ErrSessionLimitExceeded", u, err)
		}
	}
}
