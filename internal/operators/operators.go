// Package operators is an app-side registry of operator identities (Keycloak
// usernames) and the datasets assigned to them. It does NOT create Keycloak
// accounts; it records who may see which dataset. Everything is stored in the
// peat mesh so assignments travel with the edge node.
package operators

import (
	"context"
	"errors"
)

// ErrNotFound is returned when an operator or dataset is missing.
var ErrNotFound = errors.New("not found")

// Dataset kinds.
const (
	KindPilots  = "pilots"
	KindGeneric = "generic"
)

// Operator is an app-side operator record keyed by Keycloak username.
type Operator struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
}

// ViewConfig is how a dataset is visualized (configurable per dataset).
type ViewConfig struct {
	Type    string `json:"type"`     // "table" (default) | "wheel"
	GroupBy string `json:"group_by"` // column to group by for the wheel
}

// Dataset is a registered dataset and the operators assigned to it.
type Dataset struct {
	Key        string     `json:"key"`        // "pilots" or the generic collection name
	Name       string     `json:"name"`       // display name
	Kind       string     `json:"kind"`       // KindPilots | KindGeneric
	Collection string     `json:"collection"` // peat collection backing it
	AssignedTo []string   `json:"assigned_to"`
	View       ViewConfig `json:"view"`
}

// AssignedToUser reports whether username is assigned to the dataset.
func (d Dataset) AssignedToUser(username string) bool {
	for _, u := range d.AssignedTo {
		if u == username {
			return true
		}
	}
	return false
}

// Store persists operators and dataset assignments.
type Store interface {
	PutOperator(ctx context.Context, o Operator) error
	ListOperators(ctx context.Context) ([]Operator, error)
	DeleteOperator(ctx context.Context, username string) error

	PutDataset(ctx context.Context, d Dataset) error
	GetDataset(ctx context.Context, key string) (Dataset, error)
	ListDatasets(ctx context.Context) ([]Dataset, error)
}
