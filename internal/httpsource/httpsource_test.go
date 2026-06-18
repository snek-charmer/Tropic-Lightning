package httpsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseunicorns/keycloak-portal/internal/dataset"
)

func TestCreateRootArray(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1,"name":"a","active":true},{"id":2,"name":"b","active":false}]`))
	}))
	defer api.Close()

	dstore := dataset.NewMemoryStore()
	svc := NewService(NewMemoryStore(), dstore, nil)
	ctx := context.Background()

	c, err := svc.CreateConnector(ctx, Input{Name: "Assets", URL: api.URL})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.Collection != "api_assets" {
		t.Errorf("collection = %q", c.Collection)
	}
	_, cols, err := dstore.Meta(ctx, c.Collection)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	// Columns are the sorted union of keys.
	if len(cols) != 3 || cols[0] != "active" || cols[1] != "id" || cols[2] != "name" {
		t.Errorf("cols = %v", cols)
	}
	rows, _ := dstore.ListRows(ctx, c.Collection)
	if len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
	// Scalars are stringified.
	if rows[0].Fields["id"] != "1" || rows[0].Fields["active"] != "true" {
		t.Errorf("row0 = %v", rows[0].Fields)
	}
}

func TestCreateWithRecordPathAndAuth(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":{"n":1},"data":{"items":[{"k":"v1"},{"k":"v2"},{"k":"v3"}]}}`))
	}))
	defer api.Close()

	dstore := dataset.NewMemoryStore()
	svc := NewService(NewMemoryStore(), dstore, nil)
	ctx := context.Background()

	c, err := svc.CreateConnector(ctx, Input{
		Name: "Nested", URL: api.URL, RecordPath: "data.items",
		AuthType: AuthHeader, HeaderName: "X-API-Key", AuthValue: "secret123",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rows, _ := dstore.ListRows(ctx, c.Collection)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
}

func TestAuthFailureSurfaces(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer api.Close()
	svc := NewService(NewMemoryStore(), dataset.NewMemoryStore(), nil)
	if _, err := svc.CreateConnector(context.Background(), Input{Name: "x", URL: api.URL}); err == nil {
		t.Error("expected error when the API returns 401")
	}
}

func TestRefreshReplacesSnapshot(t *testing.T) {
	// The API returns 3 records first, then 1 — the connector must drop the
	// surplus rows rather than leave stale ones.
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls == 0 {
			_, _ = w.Write([]byte(`[{"id":1},{"id":2},{"id":3}]`))
		} else {
			_, _ = w.Write([]byte(`[{"id":9}]`))
		}
		calls++
	}))
	defer api.Close()

	dstore := dataset.NewMemoryStore()
	svc := NewService(NewMemoryStore(), dstore, nil)
	ctx := context.Background()
	c, err := svc.CreateConnector(ctx, Input{Name: "Snap", URL: api.URL})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rows, _ := dstore.ListRows(ctx, c.Collection); len(rows) != 3 {
		t.Fatalf("initial rows = %d", len(rows))
	}
	found, err := svc.RefreshOne(ctx, c.Collection)
	if err != nil || !found {
		t.Fatalf("refresh = %v, %v", found, err)
	}
	rows, _ := dstore.ListRows(ctx, c.Collection)
	if len(rows) != 1 || rows[0].Fields["id"] != "9" {
		t.Errorf("after refresh rows = %v", rows)
	}
}

func TestValidation(t *testing.T) {
	svc := NewService(NewMemoryStore(), dataset.NewMemoryStore(), nil)
	ctx := context.Background()
	if _, err := svc.CreateConnector(ctx, Input{Name: "", URL: "https://x"}); err == nil {
		t.Error("expected error for empty name")
	}
	if _, err := svc.CreateConnector(ctx, Input{Name: "x", URL: "ftp://nope"}); err == nil {
		t.Error("expected error for non-http URL")
	}
	if _, err := svc.CreateConnector(ctx, Input{Name: "x", URL: "https://x", AuthType: AuthHeader}); err == nil {
		t.Error("expected error: header auth without a header name")
	}
}

func TestNavigateAndStringify(t *testing.T) {
	if _, err := navigate(map[string]any{"a": "b"}, ""); err == nil {
		t.Error("root non-array with empty path should error")
	}
	arr, err := navigate(map[string]any{"a": map[string]any{"b": []any{1.0, 2.0}}}, "a.b")
	if err != nil || len(arr) != 2 {
		t.Errorf("navigate a.b = %v, %v", arr, err)
	}
	if got := stringify(map[string]any{"x": 1.0}); got != `{"x":1}` {
		t.Errorf("stringify object = %q", got)
	}
}

func TestHTMLResponseGivesClearError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>Moved</body></html>"))
	}))
	defer api.Close()
	svc := NewService(NewMemoryStore(), dataset.NewMemoryStore(), nil)
	_, err := svc.CreateConnector(context.Background(), Input{Name: "x", URL: api.URL})
	if err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("want a 'not JSON' error, got %v", err)
	}
}

func TestEmptyResponseGivesClearError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer api.Close()
	svc := NewService(NewMemoryStore(), dataset.NewMemoryStore(), nil)
	_, err := svc.CreateConnector(context.Background(), Input{Name: "x", URL: api.URL})
	if err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Errorf("want an 'empty response' error, got %v", err)
	}
}
