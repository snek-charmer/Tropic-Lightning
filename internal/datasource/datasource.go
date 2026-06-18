// Package datasource implements the admin-managed "data source" feature: a
// catalog of external system connections. Records are stored in a peat mesh
// node (a local-first CRDT datastore), so the application keeps working while
// disconnected and the peat node reconciles state across the mesh on its own
// when connectivity returns.
package datasource

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrNotFound is returned when a data source does not exist.
var ErrNotFound = errors.New("data source not found")

// DataSource is an external system the application can connect to (a database,
// object store, HTTP API, message broker, etc.). It is stored as a JSON
// document in the peat mesh; sync across nodes is handled by peat.
type DataSource struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
	// SecretRef points at where credentials live (e.g. a Kubernetes Secret name
	// or vault path). The application never stores raw credentials.
	SecretRef string    `json:"secret_ref,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MeshStatus reflects the peat node's current mesh participation, surfaced in
// the UI so operators can see whether they are connected or operating
// disconnected.
type MeshStatus struct {
	NodeID         string `json:"node_id"`
	SyncActive     bool   `json:"sync_active"`
	ConnectedPeers uint32 `json:"connected_peers"`
}

// StatusProvider reports the mesh status of the backing store.
type StatusProvider interface {
	Status(ctx context.Context) (MeshStatus, error)
}

// KnownTypes are the connection types offered in the UI. "other" is a catch-all.
var KnownTypes = []string{"postgres", "mysql", "s3", "http", "mqtt", "kafka", "file", "other"}

// ValidationError is a user-facing input error (maps to HTTP 400).
type ValidationError struct{ Msg string }

func (e ValidationError) Error() string { return e.Msg }

// Input is the set of fields a caller may set when creating a data source.
// JSON tags match the DataSource representation so the API is symmetric.
type Input struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Endpoint  string `json:"endpoint"`
	SecretRef string `json:"secret_ref"`
	Enabled   bool   `json:"enabled"`
}

// Validate checks the input and normalises whitespace.
func (in *Input) Validate() error {
	in.Name = strings.TrimSpace(in.Name)
	in.Type = strings.TrimSpace(in.Type)
	in.Endpoint = strings.TrimSpace(in.Endpoint)
	in.SecretRef = strings.TrimSpace(in.SecretRef)

	if in.Name == "" {
		return ValidationError{"name is required"}
	}
	if in.Type == "" || !isKnownType(in.Type) {
		return ValidationError{"type must be one of: " + strings.Join(KnownTypes, ", ")}
	}
	if in.Endpoint == "" {
		return ValidationError{"endpoint is required"}
	}
	return nil
}

func isKnownType(t string) bool {
	for _, k := range KnownTypes {
		if k == t {
			return true
		}
	}
	return false
}
