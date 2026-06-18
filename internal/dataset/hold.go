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
	filename string
	data     []byte
	expires  time.Time
}

// NewHold returns a Hold with the given entry TTL.
func NewHold(ttl time.Duration) *Hold {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Hold{items: map[string]heldItem{}, ttl: ttl, now: time.Now}
}

// Put stores raw uploaded bytes and returns a token to retrieve them.
func (h *Hold) Put(filename string, data []byte) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.gc()
	h.items[token] = heldItem{filename: filename, data: data, expires: h.now().Add(h.ttl)}
	return token, nil
}

// Get returns a held upload's filename + raw bytes if present and unexpired.
func (h *Hold) Get(token string) (string, []byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	it, ok := h.items[token]
	if !ok || h.now().After(it.expires) {
		return "", nil, false
	}
	return it.filename, it.data, true
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
