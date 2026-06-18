package weather

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultBaseURL is the Open-Meteo current-conditions endpoint.
const defaultBaseURL = "https://api.open-meteo.com/v1/forecast"

// DatasetWriter is the slice of the dataset store the connector needs: it
// creates the dataset schema and upserts a row per location. dataset.PeatStore
// and dataset.MemoryStore both satisfy it.
type DatasetWriter interface {
	PutMeta(ctx context.Context, collection, name string, cols []string) error
	PutRow(ctx context.Context, collection, id string, fields map[string]string) error
}

// Service configures weather connectors and refreshes their datasets.
type Service struct {
	store   Store
	rows    DatasetWriter
	client  *http.Client
	baseURL string
	log     *slog.Logger
}

// NewService wires the weather service. log may be nil.
func NewService(store Store, rows DatasetWriter, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		store:   store,
		rows:    rows,
		client:  &http.Client{Timeout: 15 * time.Second},
		baseURL: defaultBaseURL,
		log:     log,
	}
}

// SetBaseURL overrides the Open-Meteo endpoint — point it at a self-hosted
// mirror for air-gapped / DDIL deployments (or a fake server in tests).
func (s *Service) SetBaseURL(u string) {
	if u = strings.TrimSpace(u); u != "" {
		s.baseURL = u
	}
}

// ValidationError is a user-facing input error.
type ValidationError struct{ Msg string }

func (e ValidationError) Error() string { return e.Msg }

// CreateConnector registers a weather source, creates its dataset schema, and
// does a best-effort first fetch so it isn't empty.
func (s *Service) CreateConnector(ctx context.Context, name string, locs []Location) (Connector, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Connector{}, ValidationError{"a name is required"}
	}
	if len(locs) == 0 {
		return Connector{}, ValidationError{"add at least one location (label, latitude, longitude)"}
	}
	for i, l := range locs {
		if l.Lat < -90 || l.Lat > 90 || l.Lon < -180 || l.Lon > 180 {
			return Connector{}, ValidationError{fmt.Sprintf("location %d has invalid coordinates", i+1)}
		}
	}
	collection := "wx_" + slug(name)
	c := Connector{Key: collection, Name: name, Collection: collection, Locations: locs}
	if err := s.store.PutConnector(ctx, c); err != nil {
		return Connector{}, err
	}
	if err := s.rows.PutMeta(ctx, collection, name, columns); err != nil {
		return Connector{}, err
	}
	if err := s.refresh(ctx, c); err != nil {
		// Offline at creation time is fine; the poller will fill it in later.
		s.log.Warn("initial weather fetch failed", "connector", name, "err", err)
	}
	return c, nil
}

// ListConnectors returns all configured weather sources.
func (s *Service) ListConnectors(ctx context.Context) ([]Connector, error) {
	return s.store.ListConnectors(ctx)
}

// Poll refreshes every configured connector. Returns the number refreshed and
// the first error (so the caller can log connectivity issues without stopping).
func (s *Service) Poll(ctx context.Context) (int, error) {
	conns, err := s.store.ListConnectors(ctx)
	if err != nil {
		return 0, err
	}
	var firstErr error
	n := 0
	for _, c := range conns {
		if err := s.refresh(ctx, c); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n++
	}
	return n, firstErr
}

// current is the subset of the Open-Meteo response we read.
type current struct {
	Current struct {
		Time        string  `json:"time"`
		Temperature float64 `json:"temperature_2m"`
		WindSpeed   float64 `json:"wind_speed_10m"`
		WeatherCode int     `json:"weather_code"`
	} `json:"current"`
}

// refresh fetches each location's current conditions and upserts a stable row.
func (s *Service) refresh(ctx context.Context, c Connector) error {
	for i, loc := range c.Locations {
		cur, err := s.fetch(ctx, loc.Lat, loc.Lon)
		if err != nil {
			return err
		}
		fields := map[string]string{
			"location":      loc.Label,
			"latitude":      strconv.FormatFloat(loc.Lat, 'f', -1, 64),
			"longitude":     strconv.FormatFloat(loc.Lon, 'f', -1, 64),
			"temperature_c": strconv.FormatFloat(cur.Current.Temperature, 'f', 1, 64),
			"wind_kph":      strconv.FormatFloat(cur.Current.WindSpeed, 'f', 1, 64),
			"weather":       wmoText(cur.Current.WeatherCode),
			"observed_at":   cur.Current.Time,
		}
		// Index-keyed so repeated polls update the same row in place.
		if err := s.rows.PutRow(ctx, c.Collection, fmt.Sprintf("loc%03d", i+1), fields); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) fetch(ctx context.Context, lat, lon float64) (current, error) {
	q := url.Values{}
	q.Set("latitude", strconv.FormatFloat(lat, 'f', -1, 64))
	q.Set("longitude", strconv.FormatFloat(lon, 'f', -1, 64))
	q.Set("current", "temperature_2m,wind_speed_10m,weather_code")
	q.Set("temperature_unit", "celsius")
	q.Set("wind_speed_unit", "kmh")
	q.Set("timezone", "auto")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return current{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return current{}, fmt.Errorf("open-meteo request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return current{}, fmt.Errorf("open-meteo returned %d", resp.StatusCode)
	}
	var cur current
	if err := json.NewDecoder(resp.Body).Decode(&cur); err != nil {
		return current{}, fmt.Errorf("decoding open-meteo response: %w", err)
	}
	return cur, nil
}
