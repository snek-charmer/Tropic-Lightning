// Package dataset handles admin file uploads: parse a CSV/XLSX, preview it,
// drop unwanted columns, and ingest the kept columns into the peat mesh as a
// generic dataset (one JSON document per row in a named collection).
package dataset

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xuri/excelize/v2"
)

// Parsed is a tabular file read into memory: a header row plus data rows. Every
// row is normalised to len(Columns) cells. Delimiter is the CSV delimiter used
// (name; empty for XLSX).
type Parsed struct {
	Filename  string
	Columns   []string
	Rows      [][]string
	Delimiter string
}

// supported CSV delimiters, in detection-priority order.
var delimiters = []struct {
	name string
	r    rune
}{
	{"comma", ','},
	{"tab", '\t'},
	{"pipe", '|'},
	{"semicolon", ';'},
}

// DelimiterRune maps a delimiter name to its rune (0 = unknown/auto).
func DelimiterRune(name string) rune {
	for _, d := range delimiters {
		if d.name == name {
			return d.r
		}
	}
	return 0
}

// DelimiterName maps a rune to its delimiter name (defaults to "comma").
func DelimiterName(r rune) string {
	for _, d := range delimiters {
		if d.r == r {
			return d.name
		}
	}
	return "comma"
}

// DelimiterNames lists the selectable delimiter names (for the UI).
func DelimiterNames() []string {
	out := make([]string, len(delimiters))
	for i, d := range delimiters {
		out[i] = d.name
	}
	return out
}

// DetectDelimiter sniffs the first non-empty line and picks the delimiter with
// the most occurrences (defaults to comma).
func DetectDelimiter(data []byte) rune {
	line := ""
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			line = l
			break
		}
	}
	best, bestN := ',', 0
	for _, d := range delimiters {
		if n := strings.Count(line, string(d.r)); n > bestN {
			best, bestN = d.r, n
		}
	}
	return best
}

// Parse reads a CSV or XLSX file. For CSV, comma is the delimiter; comma == 0
// auto-detects it. For XLSX the delimiter is ignored.
func Parse(filename string, data []byte, comma rune) (Parsed, error) {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".csv":
		if comma == 0 {
			comma = DetectDelimiter(data)
		}
		return parseCSV(filename, data, comma)
	case ".xlsx":
		return parseXLSX(filename, data)
	default:
		return Parsed{}, fmt.Errorf("unsupported file type %q (use .csv or .xlsx)", filepath.Ext(filename))
	}
}

func parseCSV(filename string, data []byte, comma rune) (Parsed, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = comma
	r.FieldsPerRecord = -1 // tolerate ragged rows
	recs, err := r.ReadAll()
	if err != nil {
		return Parsed{}, fmt.Errorf("reading CSV: %w", err)
	}
	p, err := fromRecords(filename, recs)
	if err != nil {
		return Parsed{}, err
	}
	p.Delimiter = DelimiterName(comma)
	return p, nil
}

func parseXLSX(filename string, data []byte) (Parsed, error) {
	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		return Parsed{}, fmt.Errorf("opening xlsx: %w", err)
	}
	defer f.Close()
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return Parsed{}, fmt.Errorf("workbook has no sheets")
	}
	recs, err := f.GetRows(sheets[0])
	if err != nil {
		return Parsed{}, fmt.Errorf("reading sheet %q: %w", sheets[0], err)
	}
	return fromRecords(filename, recs)
}

// fromRecords turns raw rows into a Parsed, using row 0 as headers and padding/
// truncating data rows to the header width.
func fromRecords(filename string, recs [][]string) (Parsed, error) {
	if len(recs) == 0 {
		return Parsed{}, fmt.Errorf("file has no rows")
	}
	cols := make([]string, len(recs[0]))
	for i, c := range recs[0] {
		c = strings.TrimSpace(c)
		if c == "" {
			c = fmt.Sprintf("column_%d", i+1)
		}
		cols[i] = c
	}
	rows := make([][]string, 0, len(recs)-1)
	for _, rec := range recs[1:] {
		row := make([]string, len(cols))
		for i := range cols {
			if i < len(rec) {
				row[i] = strings.TrimSpace(rec[i])
			}
		}
		rows = append(rows, row)
	}
	return Parsed{Filename: filename, Columns: cols, Rows: rows}, nil
}
