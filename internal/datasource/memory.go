package datasource

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore is an in-memory Store implementation used in tests and as a
// fallback. It is safe for concurrent use. It also implements StatusProvider,
// reporting a single-node (disconnected) mesh.
type MemoryStore struct {
	mu   sync.Mutex
	data map[string]DataSource
	// now is injectable so tests can control timestamps.
	now func() time.Time
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: map[string]DataSource{}, now: func() time.Time { return time.Now().UTC() }}
}

func (s *MemoryStore) Create(_ context.Context, ds DataSource) (DataSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ds.ID == "" {
		ds.ID = uuid.NewString()
	}
	t := s.now()
	ds.CreatedAt, ds.UpdatedAt = t, t
	s.data[ds.ID] = ds
	return ds, nil
}

func (s *MemoryStore) List(_ context.Context) ([]DataSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DataSource, 0, len(s.data))
	for _, ds := range s.data {
		out = append(out, ds)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (DataSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, ok := s.data[id]
	if !ok {
		return DataSource{}, ErrNotFound
	}
	return ds, nil
}

func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; !ok {
		return ErrNotFound
	}
	delete(s.data, id)
	return nil
}

func (s *MemoryStore) SetEnabled(_ context.Context, id string, enabled bool) (DataSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, ok := s.data[id]
	if !ok {
		return DataSource{}, ErrNotFound
	}
	ds.Enabled = enabled
	ds.UpdatedAt = s.now()
	s.data[id] = ds
	return ds, nil
}

// Status reports a disconnected single-node mesh (the in-memory store has no
// peers).
func (s *MemoryStore) Status(context.Context) (MeshStatus, error) {
	return MeshStatus{NodeID: "memory", SyncActive: false, ConnectedPeers: 0}, nil
}
