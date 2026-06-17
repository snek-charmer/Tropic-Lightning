package datasource

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	sidecarv1 "github.com/defenseunicorns/keycloak-portal/internal/peat/sidecarv1"
)

// fakeSidecar is an in-memory implementation of the PeatSidecar document API,
// enough to exercise PeatStore end-to-end without a real peat node.
type fakeSidecar struct {
	sidecarv1.UnimplementedPeatSidecarServer
	docs map[string]map[string]string // collection -> doc_id -> json
}

func newFakeSidecar() *fakeSidecar {
	return &fakeSidecar{docs: map[string]map[string]string{}}
}

func (f *fakeSidecar) PutDocument(_ context.Context, r *sidecarv1.PutDocumentRequest) (*sidecarv1.PutDocumentResponse, error) {
	if f.docs[r.Collection] == nil {
		f.docs[r.Collection] = map[string]string{}
	}
	f.docs[r.Collection][r.DocId] = r.JsonData
	return &sidecarv1.PutDocumentResponse{}, nil
}

func (f *fakeSidecar) GetDocument(_ context.Context, r *sidecarv1.GetDocumentRequest) (*sidecarv1.GetDocumentResponse, error) {
	if c, ok := f.docs[r.Collection]; ok {
		if v, ok := c[r.DocId]; ok {
			return &sidecarv1.GetDocumentResponse{JsonData: &v}, nil
		}
	}
	return &sidecarv1.GetDocumentResponse{}, nil // not found -> nil JsonData
}

func (f *fakeSidecar) DeleteDocument(_ context.Context, r *sidecarv1.DeleteDocumentRequest) (*sidecarv1.DeleteDocumentResponse, error) {
	delete(f.docs[r.Collection], r.DocId)
	return &sidecarv1.DeleteDocumentResponse{}, nil
}

func (f *fakeSidecar) ListDocuments(_ context.Context, r *sidecarv1.ListDocumentsRequest) (*sidecarv1.ListDocumentsResponse, error) {
	var ids []string
	for id := range f.docs[r.Collection] {
		ids = append(ids, id)
	}
	return &sidecarv1.ListDocumentsResponse{DocIds: ids}, nil
}

func (f *fakeSidecar) GetStatus(context.Context, *sidecarv1.GetStatusRequest) (*sidecarv1.GetStatusResponse, error) {
	return &sidecarv1.GetStatusResponse{NodeId: "fake-node", SyncActive: true, ConnectedPeers: 3}, nil
}

// newTestPeatStore spins up the fake sidecar over an in-process bufconn and
// returns a PeatStore wired to it.
func newTestPeatStore(t *testing.T) *PeatStore {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	sidecarv1.RegisterPeatSidecarServer(srv, newFakeSidecar())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return newPeatStore(conn, "data_sources")
}

func TestPeatStoreCRUD(t *testing.T) {
	store := newTestPeatStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, DataSource{Name: "telemetry", Type: "postgres", Endpoint: "postgres://h", SecretRef: "k8s/db", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" || created.CreatedAt.IsZero() {
		t.Fatalf("created = %+v", created)
	}

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "telemetry" || got.SecretRef != "k8s/db" || !got.Enabled {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	list, err := store.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v (len %d), err %v", list, len(list), err)
	}

	upd, err := store.SetEnabled(ctx, created.ID, false)
	if err != nil || upd.Enabled {
		t.Fatalf("setEnabled = %+v, %v", upd, err)
	}

	if err := store.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v, want ErrNotFound", err)
	}
}

func TestPeatStoreStatus(t *testing.T) {
	store := newTestPeatStore(t)
	st, err := store.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.NodeID != "fake-node" || !st.SyncActive || st.ConnectedPeers != 3 {
		t.Errorf("status = %+v", st)
	}
}
