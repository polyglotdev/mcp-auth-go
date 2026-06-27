package auth

import (
	"errors"
	"sync"
	"time"
)

// SessionStore tracks active sessions per user so a service can enforce
// per-user concurrency caps and timeouts. Implementations must be safe for
// concurrent use by multiple goroutines.
//
// The interface is small on purpose -- an in-memory implementation ships here
// ([NewMemorySessionStore]); a service that scales beyond one task can swap in
// Redis without touching callers.
type SessionStore interface {
	// Open registers a new session for the user. It returns a session id
	// (opaque to callers) and an error if the user is already at the
	// concurrency cap. Open also reaps any of the user's sessions whose
	// timeout has fired before checking the cap.
	Open(userID string, now time.Time) (string, error)

	// Touch updates the session's last-seen timestamp so sliding timeouts
	// don't expire active sessions. It returns ErrInvalidSession if the
	// session id is unknown or already expired.
	Touch(sessionID string, now time.Time) error

	// Close ends a session early. It is a no-op if the session is already
	// closed or unknown.
	Close(sessionID string)

	// Count returns the number of currently-active sessions for userID.
	Count(userID string, now time.Time) int
}

// ErrInvalidSession is returned by Touch when the session id is unknown or has
// already expired.
var ErrInvalidSession = errors.New("auth: invalid or expired session")

// SessionConfig configures the in-memory session store.
type SessionConfig struct {
	// Timeout is the sliding inactivity timeout after which a session is
	// considered closed. Touch resets it. Zero disables timeouts.
	Timeout time.Duration

	// MaxConcurrentPerUser is the maximum number of active sessions a single
	// user id can hold open simultaneously. The (N+1)th Open returns
	// ErrSessionLimitExceeded. Zero or negative disables the cap.
	MaxConcurrentPerUser int
}

// memorySession is the value stored in the in-memory map.
type memorySession struct {
	userID   string
	lastSeen time.Time
}

// memoryStore is the default SessionStore. It is thread-safe via a single
// mutex; contention is not a concern at expected request rates.
type memoryStore struct {
	cfg      SessionConfig
	mu       sync.Mutex
	sessions map[string]*memorySession // sessionID -> session
	newID    func() string             // injection point for deterministic tests
}

// NewMemorySessionStore returns an in-memory SessionStore. Sessions are lost
// when the process restarts. Pass idFn to inject a deterministic id generator
// in tests; a nil idFn uses a cryptographically-random one.
//
// The returned store is safe for concurrent use by multiple goroutines.
func NewMemorySessionStore(cfg SessionConfig, idFn func() string) SessionStore {
	if idFn == nil {
		idFn = randomSessionID
	}
	return &memoryStore{
		cfg:      cfg,
		sessions: make(map[string]*memorySession),
		newID:    idFn,
	}
}

func (s *memoryStore) Open(userID string, now time.Time) (string, error) {
	if userID == "" {
		return "", errors.New("auth: empty userID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Sweep expired sessions for this user before checking the cap. Cheaper
	// than a background goroutine for the expected session counts.
	s.reapForUserLocked(userID, now)

	if s.cfg.MaxConcurrentPerUser > 0 && s.countForUserLocked(userID) >= s.cfg.MaxConcurrentPerUser {
		return "", ErrSessionLimitExceeded
	}

	id := s.newID()
	s.sessions[id] = &memorySession{userID: userID, lastSeen: now}
	return id, nil
}

func (s *memoryStore) Touch(sessionID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrInvalidSession
	}
	if s.cfg.Timeout > 0 && now.Sub(sess.lastSeen) > s.cfg.Timeout {
		delete(s.sessions, sessionID)
		return ErrInvalidSession
	}
	sess.lastSeen = now
	return nil
}

func (s *memoryStore) Close(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func (s *memoryStore) Count(userID string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapForUserLocked(userID, now)
	return s.countForUserLocked(userID)
}

// reapForUserLocked removes expired sessions for a single user. The caller
// holds s.mu.
func (s *memoryStore) reapForUserLocked(userID string, now time.Time) {
	if s.cfg.Timeout <= 0 {
		return
	}
	for id, sess := range s.sessions {
		if sess.userID == userID && now.Sub(sess.lastSeen) > s.cfg.Timeout {
			delete(s.sessions, id)
		}
	}
}

func (s *memoryStore) countForUserLocked(userID string) int {
	n := 0
	for _, sess := range s.sessions {
		if sess.userID == userID {
			n++
		}
	}
	return n
}
