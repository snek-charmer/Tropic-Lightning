package datasource

import "context"

// Store is the persistence contract for data sources. The peat-backed
// implementation is the source of truth: it stores records in the local peat
// node, which persists them and syncs across the mesh via CRDT.
type Store interface {
	Create(ctx context.Context, ds DataSource) (DataSource, error)
	List(ctx context.Context) ([]DataSource, error)
	Get(ctx context.Context, id string) (DataSource, error)
	Delete(ctx context.Context, id string) error
	SetEnabled(ctx context.Context, id string, enabled bool) (DataSource, error)
}
