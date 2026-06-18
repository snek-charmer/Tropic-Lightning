// Package deck is a shared "meeting deck": a named space where users publish
// their filtered dataset visuals as slides. Slides store a live spec (dataset +
// filter + visualization) and are re-rendered when the deck is opened, so a
// meeting can be run from the platform against current data. Decks and slides
// live in the peat mesh and are visible to any authenticated user.
package deck

import "errors"

// ErrNotFound is returned when a deck is missing.
var ErrNotFound = errors.New("deck not found")

// Deck is a shared collection of published visuals.
type Deck struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

// Slide is one published visual: a live reference to a dataset view (filter +
// visualization) plus presentation metadata.
type Slide struct {
	ID          string `json:"id"`
	DeckID      string `json:"deck_id"`
	Title       string `json:"title"`
	Collection  string `json:"collection"`   // dataset/combined collection
	DatasetName string `json:"dataset_name"` // display fallback if the source is gone

	// filter
	FilterCol string `json:"filter_col"`
	FilterVal string `json:"filter_val"`
	Query     string `json:"query"`

	// visualization
	ViewType string `json:"view_type"` // table | wheel | bar | line | stats
	GroupBy  string `json:"group_by"`
	ValueCol string `json:"value_col"`
	Agg      string `json:"agg"`

	PublishedBy string `json:"published_by"`
	PublishedAt string `json:"published_at"`
}
