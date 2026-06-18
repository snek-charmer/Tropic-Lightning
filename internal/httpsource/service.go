package httpsource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseunicorns/keycloak-portal/internal/dataset"
)

// maxRows caps how many records a single fetch ingests (each row is a peat write).
const maxRows = 2000

// maxBodyBytes caps how much of a response we read into memory.
const maxBodyBytes = 32 << 20 // 32 MiB

// DatasetWriter is the slice of the dataset store the connector needs. It writes
// a fresh snapshot each refresh (write by index, delete surplus rows).
// dataset.PeatStore and dataset.MemoryStore both satisfy it.
type DatasetWriter interface {
	PutMeta(ctx context.Context, collection, name string, cols []string) error
	PutRow(ctx context.Context, collection, id string, fields map[string]string) error
	DeleteRow(ctx context.Context, collection, id string) error
	ListRows(ctx context.Context, collection string) ([]dataset.Row, error)
}

// Service configures HTTP/JSON connectors and refreshes their datasets.
type Service struct {
	store  Store
	rows   DatasetWriter
	client *http.Client
	log    *slog.Logger
}

// NewService wires the HTTP-source service. log may be nil.
func NewService(store Store, rows DatasetWriter, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: store, rows: rows, client: &http.Client{Timeout: 20 * time.Second}, log: log}
}

// ValidationError is a user-facing input error.
type ValidationError struct{ Msg string }

func (e ValidationError) Error() string { return e.Msg }

// Input is the create form for an HTTP/JSON connector.
type Input struct {
	Name       string
	URL        string
	RecordPath string
	AuthType   string
	HeaderName string
	AuthValue  string
}

// CreateConnector validates the input, fetches once to discover the schema (so a
// bad URL/auth fails immediately), then persists the connector + first snapshot.
func (s *Service) CreateConnector(ctx context.Context, in Input) (Connector, error) {
	name := strings.TrimSpace(in.Name)
	url := strings.TrimSpace(in.URL)
	if name == "" {
		return Connector{}, ValidationError{"a name is required"}
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return Connector{}, ValidationError{"URL must start with http:// or https://"}
	}
	authType := strings.TrimSpace(in.AuthType)
	if authType == "" {
		authType = AuthNone
	}
	if authType != AuthNone && authType != AuthHeader && authType != AuthBearer {
		return Connector{}, ValidationError{"auth type must be none, header, or bearer"}
	}
	if authType == AuthHeader && strings.TrimSpace(in.HeaderName) == "" {
		return Connector{}, ValidationError{"header auth needs a header name (e.g. X-API-Key)"}
	}
	c := Connector{
		Key:        "api_" + slug(name),
		Name:       name,
		Collection: "api_" + slug(name),
		URL:        url,
		RecordPath: strings.TrimSpace(in.RecordPath),
		AuthType:   authType,
		HeaderName: strings.TrimSpace(in.HeaderName),
		AuthValue:  in.AuthValue,
	}

	recs, err := s.fetch(ctx, c)
	if err != nil {
		return Connector{}, fmt.Errorf("fetching %s: %w", c.URL, err)
	}
	if len(recs) == 0 {
		return Connector{}, ValidationError{"the response had no records — check the URL and record path"}
	}
	if err := s.store.PutConnector(ctx, c); err != nil {
		return Connector{}, err
	}
	if err := s.write(ctx, c, recs); err != nil {
		return Connector{}, err
	}
	return c, nil
}

// ListConnectors returns all configured HTTP sources.
func (s *Service) ListConnectors(ctx context.Context) ([]Connector, error) {
	return s.store.ListConnectors(ctx)
}

// Poll refreshes every connector; returns the count refreshed and the first error.
func (s *Service) Poll(ctx context.Context) (int, error) {
	conns, err := s.store.ListConnectors(ctx)
	if err != nil {
		return 0, err
	}
	var firstErr error
	n := 0
	for _, c := range conns {
		recs, err := s.fetch(ctx, c)
		if err == nil {
			err = s.write(ctx, c, recs)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n++
	}
	return n, firstErr
}

// RefreshOne re-fetches a single connector by its collection. found is false if
// no HTTP connector backs that collection (so callers can try other sources).
func (s *Service) RefreshOne(ctx context.Context, collection string) (found bool, err error) {
	conns, err := s.store.ListConnectors(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range conns {
		if c.Collection != collection {
			continue
		}
		recs, err := s.fetch(ctx, c)
		if err != nil {
			return true, err
		}
		return true, s.write(ctx, c, recs)
	}
	return false, nil
}

// fetch performs the request (with auth), decodes JSON, navigates to the record
// path, and coerces the array into a slice of objects.
func (s *Service) fetch(ctx context.Context, c Connector) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/ld+json")
	req.Header.Set("User-Agent", "keycloak-portal/1.0")
	switch c.AuthType {
	case AuthHeader:
		req.Header.Set(c.HeaderName, c.AuthValue)
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+c.AuthValue)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// A transport-level EOF/reset is cryptic; the usual cause is an http://
		// URL that redirects to https or is blocked on port 80 by egress policy.
		if strings.HasPrefix(c.URL, "http://") {
			return nil, fmt.Errorf("%w — try an https:// URL (http often redirects or is blocked on port 80)", err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 {
		return nil, fmt.Errorf("the API returned an empty response (status %d, %s)", resp.StatusCode, resp.Header.Get("Content-Type"))
	} else if trimmed[0] == '<' {
		return nil, fmt.Errorf("the API returned %s, not JSON — check the URL", firstNonEmpty(resp.Header.Get("Content-Type"), "HTML/XML"))
	}
	var body any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}
	arr, err := navigate(body, c.RecordPath)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// navigate walks a dot-path to the records array. An empty path expects the body
// itself to be the array.
func navigate(body any, path string) ([]any, error) {
	cur := body
	if p := strings.TrimSpace(path); p != "" {
		for _, key := range strings.Split(p, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("record path %q: %q is not an object", path, key)
			}
			cur, ok = m[key]
			if !ok {
				return nil, fmt.Errorf("record path %q: key %q not found", path, key)
			}
		}
	}
	arr, ok := cur.([]any)
	if !ok {
		if path == "" {
			return nil, fmt.Errorf("response is not a JSON array — set a record path to the array")
		}
		return nil, fmt.Errorf("record path %q is not an array", path)
	}
	return arr, nil
}

// write replaces the dataset snapshot: derive columns, write rows by index, and
// delete any surplus rows left from a larger previous fetch.
func (s *Service) write(ctx context.Context, c Connector, recs []map[string]any) error {
	if len(recs) > maxRows {
		recs = recs[:maxRows]
	}
	cols := columns(recs)
	if err := s.rows.PutMeta(ctx, c.Collection, c.Name, cols); err != nil {
		return err
	}

	existing, err := s.rows.ListRows(ctx, c.Collection)
	if err != nil {
		return err
	}
	newIDs := make(map[string]bool, len(recs))
	for i, rec := range recs {
		id := fmt.Sprintf("r%06d", i+1)
		newIDs[id] = true
		fields := make(map[string]string, len(rec))
		for k, v := range rec {
			fields[k] = stringify(v)
		}
		if err := s.rows.PutRow(ctx, c.Collection, id, fields); err != nil {
			return err
		}
	}
	for _, row := range existing {
		if !newIDs[row.ID] {
			if err := s.rows.DeleteRow(ctx, c.Collection, row.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// columns returns the sorted union of top-level keys across records.
func columns(recs []map[string]any) []string {
	set := map[string]bool{}
	for _, rec := range recs {
		for k := range rec {
			set[k] = true
		}
	}
	cols := make([]string, 0, len(set))
	for k := range set {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	return cols
}

// stringify renders a JSON value as a cell string (objects/arrays as compact JSON).
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	}
}
