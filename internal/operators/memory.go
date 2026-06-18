package operators

import (
	"context"
	"sort"
	"sync"
)

// MemoryStore is an in-memory Store for tests.
type MemoryStore struct {
	mu   sync.Mutex
	ops  map[string]Operator
	sets map[string]Dataset
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{ops: map[string]Operator{}, sets: map[string]Dataset{}}
}

func (s *MemoryStore) PutOperator(_ context.Context, o Operator) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops[o.Username] = o
	return nil
}

func (s *MemoryStore) DeleteOperator(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ops, username)
	return nil
}

func (s *MemoryStore) ListOperators(_ context.Context) ([]Operator, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Operator, 0, len(s.ops))
	for _, o := range s.ops {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (s *MemoryStore) PutDataset(_ context.Context, d Dataset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets[d.Key] = d
	return nil
}

func (s *MemoryStore) GetDataset(_ context.Context, key string) (Dataset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.sets[key]
	if !ok {
		return Dataset{}, ErrNotFound
	}
	return d, nil
}

func (s *MemoryStore) ListDatasets(_ context.Context) ([]Dataset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Dataset, 0, len(s.sets))
	for _, d := range s.sets {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
