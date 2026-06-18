package dataset

import (
	"context"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
)

func TestParseCSV(t *testing.T) {
	csv := "name,age,base\nAlice,30,Hill\nBob,,Nellis\n"
	p, err := Parse("roster.csv", []byte(csv), 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.Columns) != 3 || p.Columns[0] != "name" {
		t.Fatalf("columns = %v", p.Columns)
	}
	if len(p.Rows) != 2 || p.Rows[0][0] != "Alice" || p.Rows[1][1] != "" {
		t.Errorf("rows = %v", p.Rows)
	}
}

func TestParseUnsupported(t *testing.T) {
	if _, err := Parse("data.txt", []byte("x"), 0); err == nil {
		t.Error("expected error for unsupported extension")
	}
}

func TestImportDropsColumnsAndViews(t *testing.T) {
	store := NewMemoryStore()
	catalog := datasource.NewService(datasource.NewMemoryStore())
	svc := NewService(store, catalog, nil)
	ctx := context.Background()

	csv := "name,age,ssn,base\nAlice,30,111,Hill\nBob,41,222,Nellis\n"
	token, _, err := svc.Stage("roster.csv", []byte(csv))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}

	// Keep everything except the sensitive ssn column.
	res, err := svc.Import(ctx, token, "Roster", "", []string{"name", "age", "base"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Imported != 2 || res.Capped {
		t.Fatalf("result = %+v", res)
	}

	name, cols, rows, err := svc.View(ctx, res.Collection)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if name != "Roster" {
		t.Errorf("name = %q", name)
	}
	if len(cols) != 3 {
		t.Errorf("kept cols = %v (ssn should be dropped)", cols)
	}
	for _, c := range cols {
		if c == "ssn" {
			t.Error("ssn column should have been dropped")
		}
	}
	if len(rows) != 2 || rows[0].Fields["name"] != "Alice" {
		t.Errorf("rows = %v", rows)
	}
	if _, ok := rows[0].Fields["ssn"]; ok {
		t.Error("row should not contain dropped ssn field")
	}

	// A catalog entry was registered pointing at the dataset.
	ds, _ := catalog.List(ctx)
	if len(ds) != 1 || ds[0].Endpoint != "dataset://"+res.Collection {
		t.Errorf("catalog = %+v", ds)
	}

	// Import requires at least one column, and an expired token is rejected.
	if _, err := svc.Import(ctx, token, "x", "", nil); err == nil {
		t.Error("expected error: token consumed / no columns")
	}
}

func TestHoldExpiry(t *testing.T) {
	h := NewHold(0) // defaults to 15m
	tok, err := h.Put("a.csv", []byte("x\n1\n"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, ok := h.Get(tok); !ok {
		t.Error("expected held upload")
	}
	h.Delete(tok)
	if _, _, ok := h.Get(tok); ok {
		t.Error("expected deleted upload to be gone")
	}
}

func TestParseXLSX(t *testing.T) {
	f := excelize.NewFile()
	_ = f.SetSheetRow("Sheet1", "A1", &[]any{"name", "age", "base"})
	_ = f.SetSheetRow("Sheet1", "A2", &[]any{"Alice", 30, "Hill"})
	_ = f.SetSheetRow("Sheet1", "A3", &[]any{"Bob", 41, "Nellis"})
	buf, err := f.WriteToBuffer()
	if err != nil {
		t.Fatalf("write xlsx: %v", err)
	}
	p, err := Parse("roster.xlsx", buf.Bytes(), 0)
	if err != nil {
		t.Fatalf("parse xlsx: %v", err)
	}
	if len(p.Columns) != 3 || p.Columns[2] != "base" {
		t.Fatalf("columns = %v", p.Columns)
	}
	if len(p.Rows) != 2 || p.Rows[0][0] != "Alice" || p.Rows[1][2] != "Nellis" {
		t.Errorf("rows = %v", p.Rows)
	}
}

func TestEditColumnsAndRows(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, nil, nil)
	ctx := context.Background()
	token, _, err := svc.Stage("d.csv", []byte("name,base\nAlice,Hill\n"))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	res, err := svc.Import(ctx, token, "D", "", []string{"name", "base"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	c := res.Collection

	// Add a column.
	if err := svc.AddColumn(ctx, c, "status"); err != nil {
		t.Fatalf("add column: %v", err)
	}
	if err := svc.AddColumn(ctx, c, "status"); err == nil {
		t.Error("duplicate column should error")
	}
	_, cols, _, _ := svc.View(ctx, c)
	if len(cols) != 3 || cols[2] != "status" {
		t.Fatalf("cols after add = %v", cols)
	}

	// Add a row (only known columns kept).
	if err := svc.AddRow(ctx, c, map[string]string{"name": "Bob", "base": "Nellis", "status": "ok", "junk": "x"}); err != nil {
		t.Fatalf("add row: %v", err)
	}
	_, _, rows, _ := svc.View(ctx, c)
	if len(rows) != 2 {
		t.Fatalf("rows after add = %d", len(rows))
	}
	var bob *Row
	for i := range rows {
		if rows[i].Fields["name"] == "Bob" {
			bob = &rows[i]
		}
	}
	if bob == nil || bob.Fields["status"] != "ok" {
		t.Fatalf("added row = %+v", bob)
	}
	if _, ok := bob.Fields["junk"]; ok {
		t.Error("unknown column should be ignored on add row")
	}

	// Delete the column -> removed from schema and from rows.
	if err := svc.DeleteColumn(ctx, c, "status"); err != nil {
		t.Fatalf("delete column: %v", err)
	}
	_, cols, rows, _ = svc.View(ctx, c)
	if len(cols) != 2 {
		t.Errorf("cols after delete = %v", cols)
	}
	for _, r := range rows {
		if _, ok := r.Fields["status"]; ok {
			t.Error("status field should be stripped from rows")
		}
	}

	// Delete a row.
	if err := svc.DeleteRow(ctx, c, bob.ID); err != nil {
		t.Fatalf("delete row: %v", err)
	}
	_, _, rows, _ = svc.View(ctx, c)
	if len(rows) != 1 {
		t.Errorf("rows after delete = %d, want 1", len(rows))
	}
}

func TestUpdateRowPopulatesNewColumn(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, nil, nil)
	ctx := context.Background()
	token, _, _ := svc.Stage("d.csv", []byte("name\nAlice\n"))
	res, _ := svc.Import(ctx, token, "D", "", []string{"name"})
	c := res.Collection
	_ = svc.AddColumn(ctx, c, "status")

	_, _, rows, _ := svc.View(ctx, c)
	id := rows[0].ID
	if err := svc.UpdateRow(ctx, c, id, map[string]string{"name": "Alice", "status": "sick", "junk": "x"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	_, _, rows, _ = svc.View(ctx, c)
	if rows[0].Fields["status"] != "sick" {
		t.Errorf("status not updated: %+v", rows[0].Fields)
	}
	if _, ok := rows[0].Fields["junk"]; ok {
		t.Error("unknown field should be ignored")
	}
	if err := svc.UpdateRow(ctx, c, "", nil); err == nil {
		t.Error("empty id should error")
	}
}

func TestBulkSave(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, nil, nil)
	ctx := context.Background()
	token, _, _ := svc.Stage("d.csv", []byte("name,base\nAlice,Hill\nBob,Nellis\nCarol,Luke\n"))
	res, _ := svc.Import(ctx, token, "D", "", []string{"name", "base"})
	c := res.Collection
	_, _, rows, _ := svc.View(ctx, c)
	// rows sorted by id: r000001 Alice, r000002 Bob, r000003 Carol

	br, err := svc.BulkSave(ctx, c,
		[]RowEdit{
			{ID: rows[0].ID, Fields: map[string]string{"name": "Alice", "base": "Edwards"}}, // update
			{ID: "", Fields: map[string]string{"name": "Dave", "base": "Travis"}},           // add
			{ID: "", Fields: map[string]string{"name": "", "base": ""}},                     // blank -> skipped
		},
		[]string{rows[2].ID}, // delete Carol
	)
	if err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if br.Updated != 1 || br.Added != 1 || br.Deleted != 1 {
		t.Fatalf("result = %+v", br)
	}
	_, _, rows, _ = svc.View(ctx, c)
	if len(rows) != 3 { // 3 - 1 deleted + 1 added
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	var alice, dave bool
	for _, r := range rows {
		if r.Fields["name"] == "Alice" && r.Fields["base"] == "Edwards" {
			alice = true
		}
		if r.Fields["name"] == "Dave" {
			dave = true
		}
		if r.Fields["name"] == "Carol" {
			t.Error("Carol should have been deleted")
		}
	}
	if !alice || !dave {
		t.Errorf("expected updated Alice and added Dave; rows=%v", rows)
	}
}

func TestDelimiterDetectAndReparse(t *testing.T) {
	pipe := "field1|field2|field3\na|b|c\nd|e|f\n"

	// Auto-detect picks pipe -> 3 columns, not 1.
	p, err := Parse("d.csv", []byte(pipe), 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.Columns) != 3 || p.Delimiter != "pipe" {
		t.Fatalf("auto-detect = %v cols, delim %q", len(p.Columns), p.Delimiter)
	}

	// Forcing comma sees a single column (the original bug).
	c, _ := Parse("d.csv", []byte(pipe), DelimiterRune("comma"))
	if len(c.Columns) != 1 {
		t.Errorf("comma parse cols = %d, want 1", len(c.Columns))
	}

	// Stage holds raw; Preview can re-parse with a chosen delimiter.
	svc := NewService(NewMemoryStore(), nil, nil)
	token, staged, err := svc.Stage("d.csv", []byte(pipe))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if len(staged.Columns) != 3 {
		t.Errorf("staged auto-detect cols = %d, want 3", len(staged.Columns))
	}
	forced, err := svc.Preview(token, "comma")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(forced.Columns) != 1 {
		t.Errorf("forced-comma preview cols = %d, want 1", len(forced.Columns))
	}

	// Import with the pipe delimiter yields 3 columns.
	res, err := svc.Import(context.Background(), token, "Piped", "pipe", []string{"field1", "field2", "field3"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	_, cols, rows, _ := svc.View(context.Background(), res.Collection)
	if len(cols) != 3 || len(rows) != 2 {
		t.Errorf("imported cols=%v rows=%d", cols, len(rows))
	}
}

func TestDiscover(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	_ = store.PutMeta(ctx, "ds_alpha", "Alpha", []string{"x"})
	_ = store.PutMeta(ctx, "wx_bravo", "Bravo Weather", []string{"location"})
	_ = store.PutMeta(ctx, "saved_views", "should be skipped", []string{"x"}) // reserved name
	svc := NewService(store, nil, nil)

	refs, err := svc.Discover(ctx)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	got := map[string]string{}
	for _, r := range refs {
		got[r.Collection] = r.Name
	}
	if got["ds_alpha"] != "Alpha" || got["wx_bravo"] != "Bravo Weather" {
		t.Errorf("discover = %v, want ds_alpha + wx_bravo", got)
	}
	if _, ok := got["saved_views"]; ok {
		t.Error("reserved collection should be skipped")
	}
}
