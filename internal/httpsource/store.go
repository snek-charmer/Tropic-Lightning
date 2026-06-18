package httpsource

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

const connectorsCollection = "http_connectors"

// Store persists HTTP connector configs (source of truth: peat; fake: memory).
type Store interface {
	PutConnector(ctx context.Context, c Connector) error
	ListConnectors(ctx context.Context) ([]Connector, error)
}

// PeatStore persists connector configs in the peat mesh.
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

func (s *PeatStore) PutConnector(ctx context.Context, c Connector) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.client.PutDocument(ctx, &sidecarv1.PutDocumentRequest{Collection: connectorsCollection, DocId: c.Key, JsonData: string(data)})
	if err != nil {
		return fmt.Errorf("peat PutDocument(%s/%s): %w", connectorsCollection, c.Key, err)
	}
	return nil
}

func (s *PeatStore) ListConnectors(ctx context.Context) ([]Connector, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: connectorsCollection})
	if err != nil {
		return nil, fmt.Errorf("peat ListDocuments(%s): %w", connectorsCollection, err)
	}
	ids := append([]string(nil), resp.DocIds...)
	sort.Strings(ids)
	out := make([]Connector, 0, len(ids))
	for _, id := range ids {
		got, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{Collection: connectorsCollection, DocId: id})
		if err != nil {
			return nil, fmt.Errorf("peat GetDocument(%s): %w", id, err)
		}
		if got.JsonData == nil {
			continue
		}
		var c Connector
		if err := json.Unmarshal([]byte(*got.JsonData), &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// MemoryStore is an in-memory connector store for tests and no-peat runs.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]Connector
}

// NewMemoryStore returns an empty in-memory connector store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{items: map[string]Connector{}} }

func (m *MemoryStore) PutConnector(_ context.Context, c Connector) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[c.Key] = c
	return nil
}

func (m *MemoryStore) ListConnectors(_ context.Context) ([]Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.items))
	for k := range m.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Connector, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.items[k])
	}
	return out, nil
}
