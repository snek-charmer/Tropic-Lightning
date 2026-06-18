package dataset

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"time"

	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
)

// maxImportRows caps how many rows a single upload ingests, keeping the import
// request responsive (each row is a peat write). The cap is surfaced, not silent.
const maxImportRows = 2000

// collectionPrefix namespaces uploaded datasets so they never collide with the
// reserved "data_sources" / "pilots" collections.
const collectionPrefix = "ds_"

// Service stages uploaded files, imports selected columns into peat, and reads
// them back.
type Service struct {
	store   Store
	hold    *Hold
	catalog *datasource.Service // registers the catalog entry (optional)
	log     *slog.Logger
}

// NewService wires the dataset service. catalog may be nil; log may be nil.
func NewService(store Store, catalog *datasource.Service, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: store, hold: NewHold(15 * time.Minute), catalog: catalog, log: log}
}

// Stage holds the raw upload and returns a token plus an auto-detected-delimiter
// preview.
func (s *Service) Stage(filename string, data []byte) (string, Parsed, error) {
	// Parse once up front so obvious errors (bad type, empty) surface immediately.
	p, err := Parse(filename, data, 0) // 0 = auto-detect delimiter
	if err != nil {
		return "", Parsed{}, err
	}
	token, err := s.hold.Put(filename, data)
	if err != nil {
		return "", Parsed{}, err
	}
	return token, p, nil
}

// Preview re-parses the held upload with the chosen delimiter (name; "" or
// "auto" = auto-detect). Lets the user fix mis-delimited files before importing.
func (s *Service) Preview(token, delimiter string) (Parsed, error) {
	filename, data, ok := s.hold.Get(token)
	if !ok {
		return Parsed{}, fmt.Errorf("upload expired or not found; please re-upload")
	}
	return Parse(filename, data, DelimiterRune(delimiter))
}

// ImportResult reports the outcome of an import.
type ImportResult struct {
	Collection string
	Imported   int
	Total      int
	Capped     bool
}

// Import ingests the held upload (token), re-parsed with the chosen delimiter,
// keeping only the named columns, into a peat collection derived from name, and
// registers a data-source catalog entry.
func (s *Service) Import(ctx context.Context, token, name, delimiter string, keep []string) (ImportResult, error) {
	filename, data, ok := s.hold.Get(token)
	if !ok {
		return ImportResult{}, fmt.Errorf("upload expired or not found; please re-upload")
	}
	p, err := Parse(filename, data, DelimiterRune(delimiter))
	if err != nil {
		return ImportResult{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = strings.TrimSuffix(p.Filename, "."+lastExt(p.Filename))
	}

	keepSet := map[string]bool{}
	for _, k := range keep {
		keepSet[k] = true
	}
	var idx []int
	var keptCols []string
	for i, c := range p.Columns {
		if keepSet[c] {
			idx = append(idx, i)
			keptCols = append(keptCols, c)
		}
	}
	if len(idx) == 0 {
		return ImportResult{}, fmt.Errorf("select at least one column to import")
	}

	collection := collectionPrefix + slug(name)
	if err := s.store.PutMeta(ctx, collection, name, keptCols); err != nil {
		return ImportResult{}, err
	}

	total := len(p.Rows)
	limit := total
	if limit > maxImportRows {
		limit = maxImportRows
	}
	for i := 0; i < limit; i++ {
		fields := make(map[string]string, len(idx))
		for k, ci := range idx {
			fields[keptCols[k]] = p.Rows[i][ci]
		}
		if err := s.store.PutRow(ctx, collection, fmt.Sprintf("r%06d", i+1), fields); err != nil {
			return ImportResult{}, err
		}
	}

	if s.catalog != nil {
		if _, err := s.catalog.Create(ctx, datasource.Input{
			Name:     name,
			Type:     "file",
			Endpoint: "dataset://" + collection,
			Enabled:  true,
		}); err != nil {
			s.log.Warn("registering dataset catalog entry", "err", err)
		}
	}

	s.hold.Delete(token)
	return ImportResult{Collection: collection, Imported: limit, Total: total, Capped: limit < total}, nil
}

// View returns a dataset's display name, column order, and rows.
func (s *Service) View(ctx context.Context, collection string) (string, []string, []Row, error) {
	name, cols, err := s.store.Meta(ctx, collection)
	if err != nil {
		return "", nil, nil, err
	}
	rows, err := s.store.ListRows(ctx, collection)
	if err != nil {
		return "", nil, nil, err
	}
	return name, cols, rows, nil
}

// AddColumn appends a new column to the dataset schema.
func (s *Service) AddColumn(ctx context.Context, collection, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("column name is required")
	}
	dsName, cols, err := s.store.Meta(ctx, collection)
	if err != nil {
		return err
	}
	for _, c := range cols {
		if c == name {
			return fmt.Errorf("column %q already exists", name)
		}
	}
	return s.store.PutMeta(ctx, collection, dsName, append(cols, name))
}

// DeleteColumn removes a column from the schema and strips it from every row.
func (s *Service) DeleteColumn(ctx context.Context, collection, name string) error {
	dsName, cols, err := s.store.Meta(ctx, collection)
	if err != nil {
		return err
	}
	kept := make([]string, 0, len(cols))
	found := false
	for _, c := range cols {
		if c == name {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	if !found {
		return fmt.Errorf("column %q not found", name)
	}
	if err := s.store.PutMeta(ctx, collection, dsName, kept); err != nil {
		return err
	}
	rows, err := s.store.ListRows(ctx, collection)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if _, ok := row.Fields[name]; !ok {
			continue
		}
		delete(row.Fields, name)
		if err := s.store.PutRow(ctx, collection, row.ID, row.Fields); err != nil {
			return err
		}
	}
	return nil
}

// AddRow appends a row, keeping only values for known columns.
func (s *Service) AddRow(ctx context.Context, collection string, values map[string]string) error {
	_, cols, err := s.store.Meta(ctx, collection)
	if err != nil {
		return err
	}
	fields := make(map[string]string, len(cols))
	for _, c := range cols {
		fields[c] = strings.TrimSpace(values[c])
	}
	return s.store.PutRow(ctx, collection, "r"+uuid.NewString(), fields)
}

// UpdateRow overwrites an existing row's values for the current columns (so a
// newly-added column can be populated). Unknown keys are ignored.
func (s *Service) UpdateRow(ctx context.Context, collection, id string, values map[string]string) error {
	if id == "" {
		return fmt.Errorf("row id is required")
	}
	_, cols, err := s.store.Meta(ctx, collection)
	if err != nil {
		return err
	}
	fields := make(map[string]string, len(cols))
	for _, c := range cols {
		fields[c] = strings.TrimSpace(values[c])
	}
	return s.store.PutRow(ctx, collection, id, fields)
}

// DeleteRow removes a row by ID.
func (s *Service) DeleteRow(ctx context.Context, collection, id string) error {
	return s.store.DeleteRow(ctx, collection, id)
}

// RowEdit is one row in a bulk save: an existing row (ID set) to update, or a
// new row (ID empty) to add.
type RowEdit struct {
	ID     string            `json:"id"`
	Fields map[string]string `json:"fields"`
}

// BulkResult reports what a bulk save changed.
type BulkResult struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Deleted int `json:"deleted"`
}

// BulkSave applies many row edits in one call: delete the given IDs, update
// existing rows, and add new ones. Only the current columns are kept; entirely
// empty new rows are skipped. Meta is read once.
func (s *Service) BulkSave(ctx context.Context, collection string, rows []RowEdit, deletes []string) (BulkResult, error) {
	_, cols, err := s.store.Meta(ctx, collection)
	if err != nil {
		return BulkResult{}, err
	}
	var res BulkResult
	for _, id := range deletes {
		if id == "" {
			continue
		}
		if err := s.store.DeleteRow(ctx, collection, id); err != nil {
			return res, err
		}
		res.Deleted++
	}
	for _, r := range rows {
		fields := make(map[string]string, len(cols))
		empty := true
		for _, c := range cols {
			v := strings.TrimSpace(r.Fields[c])
			fields[c] = v
			if v != "" {
				empty = false
			}
		}
		if r.ID != "" {
			if err := s.store.PutRow(ctx, collection, r.ID, fields); err != nil {
				return res, err
			}
			res.Updated++
			continue
		}
		if empty {
			continue // skip blank new rows
		}
		if err := s.store.PutRow(ctx, collection, "r"+uuid.NewString(), fields); err != nil {
			return res, err
		}
		res.Added++
	}
	return res, nil
}

// slug normalises a name into a safe collection suffix.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		out = "dataset"
	}
	return out
}

func lastExt(filename string) string {
	if i := strings.LastIndexByte(filename, '.'); i >= 0 {
		return filename[i+1:]
	}
	return ""
}
