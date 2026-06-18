package weather

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseunicorns/keycloak-portal/internal/dataset"
)

// fakeOpenMeteo returns a server that answers current-conditions requests with
// fixed values, so the connector can be tested offline/deterministically.
func fakeOpenMeteo(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("latitude") == "" || r.URL.Query().Get("longitude") == "" {
			http.Error(w, "missing coords", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"current":{"time":"2026-06-18T12:00","temperature_2m":21.4,"wind_speed_10m":11.5,"weather_code":3}}`))
	}))
}

func TestCreateConnectorWritesDataset(t *testing.T) {
	api := fakeOpenMeteo(t)
	defer api.Close()

	dstore := dataset.NewMemoryStore()
	svc := NewService(NewMemoryStore(), dstore, nil)
	svc.SetBaseURL(api.URL)

	ctx := context.Background()
	c, err := svc.CreateConnector(ctx, "AOR weather", []Location{
		{Label: "Hill AFB", Lat: 41.124, Lon: -111.973},
		{Label: "Ramstein AB", Lat: 49.437, Lon: 7.600},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.Collection != "wx_aor_weather" {
		t.Errorf("collection = %q", c.Collection)
	}

	name, cols, err := dstore.Meta(ctx, c.Collection)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if name != "AOR weather" || len(cols) != len(columns) {
		t.Errorf("meta name=%q cols=%v", name, cols)
	}
	rows, err := dstore.ListRows(ctx, c.Collection)
	if err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (one per location)", len(rows))
	}
	// Conditions from the fake API land in the row.
	r := rows[0].Fields
	if r["temperature_c"] != "21.4" || r["wind_kph"] != "11.5" || r["weather"] != "Overcast" {
		t.Errorf("row fields = %v", r)
	}
	if r["location"] == "" || r["latitude"] == "" {
		t.Errorf("location/coords not recorded: %v", r)
	}
}

func TestPollUpdatesInPlace(t *testing.T) {
	api := fakeOpenMeteo(t)
	defer api.Close()
	dstore := dataset.NewMemoryStore()
	svc := NewService(NewMemoryStore(), dstore, nil)
	svc.SetBaseURL(api.URL)
	ctx := context.Background()

	c, err := svc.CreateConnector(ctx, "wx", []Location{{Label: "A", Lat: 1, Lon: 2}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	n, err := svc.Poll(ctx)
	if err != nil || n != 1 {
		t.Fatalf("poll = %d, %v", n, err)
	}
	// Re-polling updates the same row (stable index key), not appends.
	rows, _ := dstore.ListRows(ctx, c.Collection)
	if len(rows) != 1 {
		t.Errorf("rows after re-poll = %d, want 1", len(rows))
	}
}

func TestCreateConnectorValidation(t *testing.T) {
	svc := NewService(NewMemoryStore(), dataset.NewMemoryStore(), nil)
	ctx := context.Background()
	if _, err := svc.CreateConnector(ctx, "", []Location{{Lat: 1, Lon: 2}}); err == nil {
		t.Error("expected error for empty name")
	}
	if _, err := svc.CreateConnector(ctx, "x", nil); err == nil {
		t.Error("expected error for no locations")
	}
	if _, err := svc.CreateConnector(ctx, "x", []Location{{Lat: 999, Lon: 0}}); err == nil {
		t.Error("expected error for out-of-range latitude")
	}
}

func TestWMOText(t *testing.T) {
	cases := map[int]string{0: "Clear", 3: "Overcast", 63: "Rain", 95: "Thunderstorm", 9999: "Unknown"}
	for code, want := range cases {
		if got := wmoText(code); got != want {
			t.Errorf("wmoText(%d) = %q, want %q", code, got, want)
		}
	}
}
