package dataset

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Hold is a short-lived, in-memory store of parsed uploads, bridging the
// preview step and the import step. Single-replica scoped (fine for the portal);
// entries expire after the TTL.
//
// now is injectable for tests.
type Hold struct {
	mu    sync.Mutex
	items map[string]heldItem
	ttl   time.Duration
	now   func() time.Time
}

type heldItem struct {
	parsed  Parsed
	expires time.Time
}

// NewHold returns a Hold with the given entry TTL.
func NewHold(ttl time.Duration) *Hold {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Hold{items: map[string]heldItem{}, ttl: ttl, now: time.Now}
}

// Put stores a parsed upload and returns a token to retrieve it.
func (h *Hold) Put(p Parsed) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.gc()
	h.items[token] = heldItem{parsed: p, expires: h.now().Add(h.ttl)}
	return token, nil
}

// Get returns a held upload if present and unexpired.
func (h *Hold) Get(token string) (Parsed, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	it, ok := h.items[token]
	if !ok || h.now().After(it.expires) {
		return Parsed{}, false
	}
	return it.parsed, true
}

// Delete removes a held upload (after a successful import).
func (h *Hold) Delete(token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.items, token)
}

// gc drops expired entries. Caller holds the lock.
func (h *Hold) gc() {
	now := h.now()
	for k, v := range h.items {
		if now.After(v.expires) {
			delete(h.items, k)
		}
	}
}
