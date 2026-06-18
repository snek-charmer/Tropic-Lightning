// Package views stores per-user saved views of a dataset: a named filter +
// visualization an operator can re-apply instead of re-filtering each time.
// Views are private to their owner (a Keycloak username) and stored in the peat
// mesh so they travel with the edge node.
package views

import "errors"

// ErrNotFound is returned when a view is missing.
var ErrNotFound = errors.New("view not found")

// View is a saved filter + visualization for one dataset, owned by one user.
type View struct {
	ID         string `json:"id"`
	Owner      string `json:"owner"`      // Keycloak username
	Collection string `json:"collection"` // dataset collection key
	Name       string `json:"name"`
	Default    bool   `json:"default"` // auto-applied when the owner opens the dataset

	// filter
	FilterCol string `json:"filter_col"`
	FilterVal string `json:"filter_val"`
	Query     string `json:"query"`

	// visualization (empty = use the dataset's own setting)
	ViewType string `json:"view_type"` // "" | "table" | "wheel"
	GroupBy  string `json:"group_by"`
}
