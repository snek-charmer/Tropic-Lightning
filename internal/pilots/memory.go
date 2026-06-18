package pilots

import (
	"context"
	"sort"
	"sync"
)

// MemoryStore is an in-memory Store used in tests and local runs.
type MemoryStore struct {
	mu   sync.Mutex
	data map[string]Pilot
}

// NewMemoryStore returns an empty in-memory pilots store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: map[string]Pilot{}}
}

func (s *MemoryStore) Put(_ context.Context, p Pilot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[p.PilotID] = p
	return nil
}

func (s *MemoryStore) List(_ context.Context) ([]Pilot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pilot, 0, len(s.data))
	for _, p := range s.data {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PilotID < out[j].PilotID })
	return out, nil
}

func (s *MemoryStore) Count(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data), nil
}
