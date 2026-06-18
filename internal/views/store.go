package views

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	sidecarv1 "github.com/defenseunicorns/keycloak-portal/internal/peat/sidecarv1"
)

const collection = "saved_views"

// Store persists saved views (source of truth: peat; fake: memory).
type Store interface {
	PutView(ctx context.Context, v View) error
	GetView(ctx context.Context, id string) (View, bool, error)
	ListViews(ctx context.Context) ([]View, error)
	DeleteView(ctx context.Context, id string) error
}

// PeatStore persists saved views in the peat mesh.
type PeatStore struct {
	conn   *grpc.ClientConn
	client sidecarv1.PeatSidecarClient
}

// NewPeatStore dials the peat sidecar at addr. tlsCreds may be nil (plaintext).
func NewPeatStore(addr string, tlsCreds credentials.TransportCredentials) (*PeatStore, error) {
	creds := tlsCreds
	if creds == nil {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dialing peat node %q: %w", addr, err)
	}
	return &PeatStore{conn: conn, client: sidecarv1.NewPeatSidecarClient(conn)}, nil
}

// Close releases the gRPC connection.
func (s *PeatStore) Close() error { return s.conn.Close() }

func (s *PeatStore) PutView(ctx context.Context, v View) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.client.PutDocument(ctx, &sidecarv1.PutDocumentRequest{Collection: collection, DocId: v.ID, JsonData: string(data)})
	if err != nil {
		return fmt.Errorf("peat PutDocument(%s/%s): %w", collection, v.ID, err)
	}
	return nil
}

func (s *PeatStore) GetView(ctx context.Context, id string) (View, bool, error) {
	got, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{Collection: collection, DocId: id})
	if err != nil {
		return View{}, false, fmt.Errorf("peat GetDocument(%s/%s): %w", collection, id, err)
	}
	if got.JsonData == nil {
		return View{}, false, nil
	}
	var v View
	if err := json.Unmarshal([]byte(*got.JsonData), &v); err != nil {
		return View{}, false, err
	}
	return v, true, nil
}

func (s *PeatStore) ListViews(ctx context.Context) ([]View, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: collection})
	if err != nil {
		return nil, fmt.Errorf("peat ListDocuments(%s): %w", collection, err)
	}
	ids := append([]string(nil), resp.DocIds...)
	sort.Strings(ids)
	out := make([]View, 0, len(ids))
	for _, id := range ids {
		v, ok, err := s.GetView(ctx, id)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, v)
		}
	}
	return out, nil
}

func (s *PeatStore) DeleteView(ctx context.Context, id string) error {
	_, err := s.client.DeleteDocument(ctx, &sidecarv1.DeleteDocumentRequest{Collection: collection, DocId: id})
	if err != nil {
		return fmt.Errorf("peat DeleteDocument(%s/%s): %w", collection, id, err)
	}
	return nil
}

// MemoryStore is an in-memory view store for tests and no-peat runs.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]View
}

// NewMemoryStore returns an empty in-memory view store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{items: map[string]View{}} }

func (m *MemoryStore) PutView(_ context.Context, v View) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[v.ID] = v
	return nil
}

func (m *MemoryStore) GetView(_ context.Context, id string) (View, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[id]
	return v, ok, nil
}

func (m *MemoryStore) ListViews(_ context.Context) ([]View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.items))
	for id := range m.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]View, 0, len(ids))
	for _, id := range ids {
		out = append(out, m.items[id])
	}
	return out, nil
}

func (m *MemoryStore) DeleteView(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, id)
	return nil
}
