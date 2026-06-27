package auth

import (
	"crypto/rand"
	"encoding/hex"
)

// randomSessionID returns a cryptographically-random 128-bit session id, hex
// encoded. It is the default id generator for NewMemorySessionStore.
//
// Session ids are not user-facing identifiers and should never appear in logs
// at info level, so a 128-bit space is plenty to make guessing impractical
// without being absurdly long.
func randomSessionID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand only fails if the OS RNG is broken -- treat as fatal.
		panic("auth: crypto/rand failure: " + err.Error()) // crypto/rand failure is unrecoverable; treat as fatal
	}
	return hex.EncodeToString(buf[:])
}
