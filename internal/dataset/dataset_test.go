package dataset

import (
	"context"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
)

func TestParseCSV(t *testing.T) {
	csv := "name,age,base\nAlice,30,Hill\nBob,,Nellis\n"
	p, err := Parse("roster.csv", []byte(csv))
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
	if _, err := Parse("data.txt", []byte("x")); err == nil {
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
	res, err := svc.Import(ctx, token, "Roster", []string{"name", "age", "base"})
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
	if len(rows) != 2 || rows[0]["name"] != "Alice" {
		t.Errorf("rows = %v", rows)
	}
	if _, ok := rows[0]["ssn"]; ok {
		t.Error("row should not contain dropped ssn field")
	}

	// A catalog entry was registered pointing at the dataset.
	ds, _ := catalog.List(ctx)
	if len(ds) != 1 || ds[0].Endpoint != "dataset://"+res.Collection {
		t.Errorf("catalog = %+v", ds)
	}

	// Import requires at least one column, and an expired token is rejected.
	if _, err := svc.Import(ctx, token, "x", nil); err == nil {
		t.Error("expected error: token consumed / no columns")
	}
}

func TestHoldExpiry(t *testing.T) {
	h := NewHold(0) // defaults to 15m
	tok, err := h.Put(Parsed{Filename: "a.csv", Columns: []string{"x"}})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, ok := h.Get(tok); !ok {
		t.Error("expected held upload")
	}
	h.Delete(tok)
	if _, ok := h.Get(tok); ok {
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
	p, err := Parse("roster.xlsx", buf.Bytes())
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
