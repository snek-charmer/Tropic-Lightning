package pilots

import (
	"bytes"
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

// datasetXLSX is the vendored USAF pilots synthetic dataset, embedded so import
// works air-gapped (no runtime fetch).
//
//go:embed data/usaf_pilots_synthetic.xlsx
var datasetXLSX []byte

// sheetName is the workbook sheet holding the core pilots table.
const sheetName = "pilots"

// ParseDataset reads the embedded workbook's "pilots" sheet into Pilots. Columns
// are mapped by header name (not position), so column reordering is tolerated.
func ParseDataset() ([]Pilot, error) {
	f, err := excelize.OpenReader(bytes.NewReader(datasetXLSX))
	if err != nil {
		return nil, fmt.Errorf("opening pilots dataset: %w", err)
	}
	defer f.Close()

	rows, err := f.GetRows(sheetName)
	if err != nil {
		return nil, fmt.Errorf("reading %q sheet: %w", sheetName, err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("pilots sheet has no data rows")
	}

	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.TrimSpace(h)] = i
	}

	get := func(row []string, header string) string {
		if i, ok := col[header]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}

	out := make([]Pilot, 0, len(rows)-1)
	for _, row := range rows[1:] {
		id := get(row, "pilot_id")
		if id == "" {
			continue
		}
		out = append(out, Pilot{
			PilotID:             id,
			Age:                 atoi(get(row, "age")),
			Gender:              get(row, "gender"),
			Rank:                get(row, "rank"),
			Base:                get(row, "base"),
			Aircraft:            get(row, "aircraft"),
			FlightHoursTotal:    atoi(get(row, "flight_hours_total")),
			FlightHoursLast12mo: atoi(get(row, "flight_hours_last_12mo")),
			AeromedicalClass:    get(row, "aeromedical_class_current"),
			DentalReadiness:     atoi(get(row, "dental_readiness")),
			PhaLastDate:         dateOnly(get(row, "pha_last_date")),
			PhaStatus:           get(row, "pha_status"),
		})
	}
	return out, nil
}

// atoi parses an int, tolerating empty/decimal values ("212", "212.0", "").
func atoi(s string) int {
	if s == "" {
		return 0
	}
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int(f)
	}
	return 0
}

// dateOnly trims a trailing time component ("2025-02-05 00:00:00" -> "2025-02-05").
func dateOnly(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}
