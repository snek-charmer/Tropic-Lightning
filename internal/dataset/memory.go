package dataset

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// MemoryStore is an in-memory Store used in tests.
type MemoryStore struct {
	mu   sync.Mutex
	data map[string]*memColl
}

type memColl struct {
	name string
	cols []string
	rows map[string]map[string]string
}

// NewMemoryStore returns an empty in-memory dataset store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: map[string]*memColl{}}
}

func (s *MemoryStore) coll(collection string) *memColl {
	c, ok := s.data[collection]
	if !ok {
		c = &memColl{rows: map[string]map[string]string{}}
		s.data[collection] = c
	}
	return c
}

func (s *MemoryStore) PutMeta(_ context.Context, collection, name string, cols []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.coll(collection)
	c.name, c.cols = name, cols
	return nil
}

func (s *MemoryStore) PutRow(_ context.Context, collection, id string, fields map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.coll(collection).rows[id] = fields
	return nil
}

func (s *MemoryStore) Meta(_ context.Context, collection string) (string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.data[collection]
	if !ok {
		return "", nil, fmt.Errorf("dataset %q not found", collection)
	}
	return c.name, c.cols, nil
}

func (s *MemoryStore) ListRows(_ context.Context, collection string) ([]map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.data[collection]
	if !ok {
		return nil, nil
	}
	ids := make([]string, 0, len(c.rows))
	for id := range c.rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, c.rows[id])
	}
	return out, nil
}
