package operators

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

const (
	operatorsCollection = "operators"
	datasetsCollection  = "dataset_registry"
)

// PeatStore persists operators and dataset assignments in the peat mesh.
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

func (s *PeatStore) put(ctx context.Context, collection, id string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.client.PutDocument(ctx, &sidecarv1.PutDocumentRequest{Collection: collection, DocId: id, JsonData: string(data)})
	if err != nil {
		return fmt.Errorf("peat PutDocument(%s/%s): %w", collection, id, err)
	}
	return nil
}

func (s *PeatStore) PutOperator(ctx context.Context, o Operator) error {
	return s.put(ctx, operatorsCollection, o.Username, o)
}

func (s *PeatStore) DeleteOperator(ctx context.Context, username string) error {
	_, err := s.client.DeleteDocument(ctx, &sidecarv1.DeleteDocumentRequest{Collection: operatorsCollection, DocId: username})
	if err != nil {
		return fmt.Errorf("peat DeleteDocument: %w", err)
	}
	return nil
}

func (s *PeatStore) ListOperators(ctx context.Context) ([]Operator, error) {
	ids, err := s.listIDs(ctx, operatorsCollection)
	if err != nil {
		return nil, err
	}
	out := make([]Operator, 0, len(ids))
	for _, id := range ids {
		var o Operator
		ok, err := s.get(ctx, operatorsCollection, id, &o)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}

func (s *PeatStore) PutDataset(ctx context.Context, d Dataset) error {
	return s.put(ctx, datasetsCollection, d.Key, d)
}

func (s *PeatStore) GetDataset(ctx context.Context, key string) (Dataset, error) {
	var d Dataset
	ok, err := s.get(ctx, datasetsCollection, key, &d)
	if err != nil {
		return Dataset{}, err
	}
	if !ok {
		return Dataset{}, ErrNotFound
	}
	return d, nil
}

func (s *PeatStore) ListDatasets(ctx context.Context) ([]Dataset, error) {
	ids, err := s.listIDs(ctx, datasetsCollection)
	if err != nil {
		return nil, err
	}
	out := make([]Dataset, 0, len(ids))
	for _, id := range ids {
		var d Dataset
		ok, err := s.get(ctx, datasetsCollection, id, &d)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *PeatStore) listIDs(ctx context.Context, collection string) ([]string, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: collection})
	if err != nil {
		return nil, fmt.Errorf("peat ListDocuments(%s): %w", collection, err)
	}
	ids := append([]string(nil), resp.DocIds...)
	sort.Strings(ids)
	return ids, nil
}

func (s *PeatStore) get(ctx context.Context, collection, id string, v any) (bool, error) {
	got, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{Collection: collection, DocId: id})
	if err != nil {
		return false, fmt.Errorf("peat GetDocument(%s/%s): %w", collection, id, err)
	}
	if got.JsonData == nil {
		return false, nil
	}
	if err := json.Unmarshal([]byte(*got.JsonData), v); err != nil {
		return false, err
	}
	return true, nil
}
