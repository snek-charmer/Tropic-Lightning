package pilots

import (
	"context"
	"testing"

	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
)

func TestParseDataset(t *testing.T) {
	ps, err := ParseDataset()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ps) < 100 {
		t.Fatalf("expected many pilots, got %d", len(ps))
	}
	p := ps[0]
	if p.PilotID == "" {
		t.Error("expected a pilot_id")
	}
	if p.Age <= 0 || p.FlightHoursTotal <= 0 {
		t.Errorf("numeric fields not parsed: %+v", p)
	}
	if len(p.PhaLastDate) != 10 { // YYYY-MM-DD, time component stripped
		t.Errorf("pha_last_date not normalized: %q", p.PhaLastDate)
	}
}

func TestImportPopulatesStoreAndCatalog(t *testing.T) {
	store := NewMemoryStore()
	catalog := datasource.NewService(datasource.NewMemoryStore())
	svc := NewService(store, catalog, nil)
	ctx := context.Background()

	n, err := svc.Import(ctx)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if n < 100 {
		t.Fatalf("imported %d, want many", n)
	}
	got, _ := store.Count(ctx)
	if got != n {
		t.Errorf("store count = %d, want %d", got, n)
	}

	// A catalog data-source entry was registered, and re-import is idempotent.
	ds, _ := catalog.List(ctx)
	if len(ds) != 1 {
		t.Fatalf("catalog entries = %d, want 1", len(ds))
	}
	if _, err := svc.Import(ctx); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	ds, _ = catalog.List(ctx)
	if len(ds) != 1 {
		t.Errorf("catalog entries after re-import = %d, want 1 (idempotent)", len(ds))
	}
}
