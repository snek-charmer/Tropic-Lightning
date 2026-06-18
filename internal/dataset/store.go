package dataset

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	sidecarv1 "github.com/defenseunicorns/keycloak-portal/internal/peat/sidecarv1"
)

// metaDocID holds a collection's column order + display name, stored alongside
// the row documents (and skipped when listing rows).
const metaDocID = "__meta__"

type metaDoc struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

// Store persists generic datasets (a meta doc + one doc per row) in named peat
// collections. Implemented by peat (source of truth) and an in-memory fake.
type Store interface {
	PutMeta(ctx context.Context, collection, name string, cols []string) error
	PutRow(ctx context.Context, collection, id string, fields map[string]string) error
	Meta(ctx context.Context, collection string) (name string, cols []string, err error)
	ListRows(ctx context.Context, collection string) ([]map[string]string, error)
}

// PeatStore writes datasets to the peat mesh via the PeatSidecar gRPC API.
type PeatStore struct {
	conn   *grpc.ClientConn
	client sidecarv1.PeatSidecarClient
}

// NewPeatStore dials the peat sidecar at addr (host:port). tlsCreds may be nil
// for the co-located sidecar pattern (plaintext).
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

func (s *PeatStore) put(ctx context.Context, collection, id string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.client.PutDocument(ctx, &sidecarv1.PutDocumentRequest{
		Collection: collection, DocId: id, JsonData: string(data),
	})
	if err != nil {
		return fmt.Errorf("peat PutDocument(%s/%s): %w", collection, id, err)
	}
	return nil
}

func (s *PeatStore) PutMeta(ctx context.Context, collection, name string, cols []string) error {
	return s.put(ctx, collection, metaDocID, metaDoc{Name: name, Columns: cols})
}

func (s *PeatStore) PutRow(ctx context.Context, collection, id string, fields map[string]string) error {
	return s.put(ctx, collection, id, fields)
}

func (s *PeatStore) Meta(ctx context.Context, collection string) (string, []string, error) {
	got, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{Collection: collection, DocId: metaDocID})
	if err != nil {
		return "", nil, fmt.Errorf("peat GetDocument(meta): %w", err)
	}
	if got.JsonData == nil {
		return "", nil, fmt.Errorf("dataset %q not found", collection)
	}
	var m metaDoc
	if err := json.Unmarshal([]byte(*got.JsonData), &m); err != nil {
		return "", nil, err
	}
	return m.Name, m.Columns, nil
}

func (s *PeatStore) ListRows(ctx context.Context, collection string) ([]map[string]string, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: collection})
	if err != nil {
		return nil, fmt.Errorf("peat ListDocuments: %w", err)
	}
	ids := make([]string, 0, len(resp.DocIds))
	for _, id := range resp.DocIds {
		if id != metaDocID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		got, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{Collection: collection, DocId: id})
		if err != nil {
			return nil, fmt.Errorf("peat GetDocument(%s): %w", id, err)
		}
		if got.JsonData == nil {
			continue
		}
		var row map[string]string
		if err := json.Unmarshal([]byte(*got.JsonData), &row); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}
