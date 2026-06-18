// Package pilots ingests the USAF pilots synthetic dataset (MHS Genesis) into
// the peat mesh as documents, simulating real data arriving on an edge node.
// The dataset is embedded in the binary so import works fully air-gapped.
package pilots

import (
	"context"
	"errors"
)

// ErrNotFound is returned when a pilot does not exist.
var ErrNotFound = errors.New("pilot not found")

// Mission status values for a pilot's availability to fly.
const (
	StatusAvailable = "available"
	StatusGrounded  = "grounded"
)

// Pilot is one row of the "pilots" sheet, plus an operator-editable mission
// status. Stored as a JSON document in the peat "pilots" collection, keyed by
// PilotID.
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

	// Operator-editable mission availability.
	MissionStatus string `json:"mission_status"`        // available | grounded
	StatusNote    string `json:"status_note,omitempty"` // e.g. "sick"
	StatusBy      string `json:"status_by,omitempty"`   // who last changed it
	StatusAt      string `json:"status_at,omitempty"`   // RFC3339 timestamp
}

// Available reports whether the pilot is available to fly missions.
func (p Pilot) Available() bool { return p.MissionStatus == StatusAvailable }

// Store persists pilots. The peat-backed implementation is the source of truth;
// an in-memory implementation is used in tests.
type Store interface {
	// Put upserts a pilot (keyed by PilotID).
	Put(ctx context.Context, p Pilot) error
	// Get returns one pilot (ErrNotFound if missing).
	Get(ctx context.Context, id string) (Pilot, error)
	// List returns all pilots.
	List(ctx context.Context) ([]Pilot, error)
	// Count returns how many pilots are stored.
	Count(ctx context.Context) (int, error)
}
