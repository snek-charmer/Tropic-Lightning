package pilots

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

// collection is the peat document collection pilots are stored in.
const collection = "pilots"

// PeatStore persists pilots as JSON documents in the peat mesh node via the
// PeatSidecar gRPC API, so they replicate across the mesh and survive
// disconnection — the same backend the data-source catalog uses.
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

func (s *PeatStore) Put(ctx context.Context, p Pilot) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.client.PutDocument(ctx, &sidecarv1.PutDocumentRequest{
		Collection: collection,
		DocId:      p.PilotID,
		JsonData:   string(data),
	})
	if err != nil {
		return fmt.Errorf("peat PutDocument(%s): %w", p.PilotID, err)
	}
	return nil
}

func (s *PeatStore) List(ctx context.Context) ([]Pilot, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: collection})
	if err != nil {
		return nil, fmt.Errorf("peat ListDocuments: %w", err)
	}
	out := make([]Pilot, 0, len(resp.DocIds))
	for _, id := range resp.DocIds {
		got, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{Collection: collection, DocId: id})
		if err != nil {
			return nil, fmt.Errorf("peat GetDocument(%s): %w", id, err)
		}
		if got.JsonData == nil {
			continue
		}
		var p Pilot
		if err := json.Unmarshal([]byte(*got.JsonData), &p); err != nil {
			return nil, fmt.Errorf("decoding pilot %s: %w", id, err)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PilotID < out[j].PilotID })
	return out, nil
}

func (s *PeatStore) Count(ctx context.Context) (int, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: collection})
	if err != nil {
		return 0, fmt.Errorf("peat ListDocuments: %w", err)
	}
	return len(resp.DocIds), nil
}
