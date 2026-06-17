package datasource

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	sidecarv1 "github.com/defenseunicorns/keycloak-portal/internal/peat/sidecarv1"
)

// PeatStore persists data sources in a peat mesh node via the PeatSidecar gRPC
// API. Each data source is a JSON document in a named collection; peat handles
// local persistence, disconnected operation, and CRDT sync across the mesh.
type PeatStore struct {
	conn       *grpc.ClientConn
	client     sidecarv1.PeatSidecarClient
	collection string
}

// NewPeatStore dials the peat sidecar at addr (host:port) and returns a store
// over the given document collection. tlsCfg may be nil for the co-located
// sidecar pattern (plaintext on a Unix socket / localhost).
func NewPeatStore(addr, collection string, tlsCreds credentials.TransportCredentials) (*PeatStore, error) {
	if collection == "" {
		collection = "data_sources"
	}
	creds := tlsCreds
	if creds == nil {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dialing peat node %q: %w", addr, err)
	}
	return newPeatStore(conn, collection), nil
}

// newPeatStore wraps an existing connection. Used by NewPeatStore and by tests
// that dial an in-process fake sidecar.
func newPeatStore(conn *grpc.ClientConn, collection string) *PeatStore {
	if collection == "" {
		collection = "data_sources"
	}
	return &PeatStore{
		conn:       conn,
		client:     sidecarv1.NewPeatSidecarClient(conn),
		collection: collection,
	}
}

// Close releases the gRPC connection.
func (s *PeatStore) Close() error { return s.conn.Close() }

func (s *PeatStore) Create(ctx context.Context, ds DataSource) (DataSource, error) {
	if ds.ID == "" {
		ds.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	ds.CreatedAt, ds.UpdatedAt = now, now
	if err := s.put(ctx, ds); err != nil {
		return DataSource{}, err
	}
	return ds, nil
}

func (s *PeatStore) Get(ctx context.Context, id string) (DataSource, error) {
	resp, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{
		Collection: s.collection,
		DocId:      id,
	})
	if err != nil {
		return DataSource{}, fmt.Errorf("peat GetDocument: %w", err)
	}
	if resp.JsonData == nil {
		return DataSource{}, ErrNotFound
	}
	return decode(*resp.JsonData)
}

func (s *PeatStore) List(ctx context.Context) ([]DataSource, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: s.collection})
	if err != nil {
		return nil, fmt.Errorf("peat ListDocuments: %w", err)
	}
	out := make([]DataSource, 0, len(resp.DocIds))
	for _, id := range resp.DocIds {
		ds, err := s.Get(ctx, id)
		if err == ErrNotFound {
			continue // listed but vanished concurrently
		}
		if err != nil {
			return nil, err
		}
		out = append(out, ds)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *PeatStore) Delete(ctx context.Context, id string) error {
	// Confirm existence so callers get ErrNotFound rather than a silent no-op.
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	_, err := s.client.DeleteDocument(ctx, &sidecarv1.DeleteDocumentRequest{
		Collection: s.collection,
		DocId:      id,
	})
	if err != nil {
		return fmt.Errorf("peat DeleteDocument: %w", err)
	}
	return nil
}

func (s *PeatStore) SetEnabled(ctx context.Context, id string, enabled bool) (DataSource, error) {
	ds, err := s.Get(ctx, id)
	if err != nil {
		return DataSource{}, err
	}
	ds.Enabled = enabled
	ds.UpdatedAt = time.Now().UTC()
	if err := s.put(ctx, ds); err != nil {
		return DataSource{}, err
	}
	return ds, nil
}

// Status maps the sidecar's GetStatus into MeshStatus.
func (s *PeatStore) Status(ctx context.Context) (MeshStatus, error) {
	resp, err := s.client.GetStatus(ctx, &sidecarv1.GetStatusRequest{})
	if err != nil {
		return MeshStatus{}, fmt.Errorf("peat GetStatus: %w", err)
	}
	return MeshStatus{
		NodeID:         resp.NodeId,
		SyncActive:     resp.SyncActive,
		ConnectedPeers: resp.ConnectedPeers,
	}, nil
}

func (s *PeatStore) put(ctx context.Context, ds DataSource) error {
	data, err := json.Marshal(ds)
	if err != nil {
		return err
	}
	_, err = s.client.PutDocument(ctx, &sidecarv1.PutDocumentRequest{
		Collection: s.collection,
		DocId:      ds.ID,
		JsonData:   string(data),
	})
	if err != nil {
		return fmt.Errorf("peat PutDocument: %w", err)
	}
	return nil
}

func decode(jsonData string) (DataSource, error) {
	var ds DataSource
	if err := json.Unmarshal([]byte(jsonData), &ds); err != nil {
		return DataSource{}, fmt.Errorf("decoding data source document: %w", err)
	}
	return ds, nil
}
