// Package pilots ingests the USAF pilots synthetic dataset (MHS Genesis) into
// the peat mesh as documents, simulating real data arriving on an edge node.
// The dataset is embedded in the binary so import works fully air-gapped.
package pilots

import "context"

// Pilot is one row of the "pilots" sheet. Stored as a JSON document in the peat
// "pilots" collection, keyed by PilotID.
type Pilot struct {
	PilotID             string `json:"pilot_id"`
	Age                 int    `json:"age"`
	Gender              string `json:"gender"`
	Rank                string `json:"rank"`
	Base                string `json:"base"`
	Aircraft            string `json:"aircraft"`
	FlightHoursTotal    int    `json:"flight_hours_total"`
	FlightHoursLast12mo int    `json:"flight_hours_last_12mo"`
	AeromedicalClass    string `json:"aeromedical_class_current"`
	DentalReadiness     int    `json:"dental_readiness"`
	PhaLastDate         string `json:"pha_last_date"`
	PhaStatus           string `json:"pha_status"`
}

// Store persists pilots. The peat-backed implementation is the source of truth;
// an in-memory implementation is used in tests.
type Store interface {
	// Put upserts a pilot (keyed by PilotID).
	Put(ctx context.Context, p Pilot) error
	// List returns all pilots.
	List(ctx context.Context) ([]Pilot, error)
	// Count returns how many pilots are stored.
	Count(ctx context.Context) (int, error)
}
