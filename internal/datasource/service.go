package datasource

import "context"

// Service is the application-facing API for data sources. It delegates
// persistence to a Store (backed by the peat node) and exposes the backing
// mesh status. There is no background sync worker — peat handles disconnected
// operation and mesh reconciliation itself.
type Service struct {
	store  Store
	status StatusProvider
}

// NewService wires a service over a store. If the store also implements
// StatusProvider (the peat and in-memory stores do), mesh status is available.
func NewService(store Store) *Service {
	svc := &Service{store: store}
	if sp, ok := store.(StatusProvider); ok {
		svc.status = sp
	}
	return svc
}

// Create validates input and persists a new data source.
func (s *Service) Create(ctx context.Context, in Input) (DataSource, error) {
	if err := in.Validate(); err != nil {
		return DataSource{}, err
	}
	return s.store.Create(ctx, DataSource{
		Name:      in.Name,
		Type:      in.Type,
		Endpoint:  in.Endpoint,
		SecretRef: in.SecretRef,
		Enabled:   in.Enabled,
	})
}

// List returns all data sources, newest first.
func (s *Service) List(ctx context.Context) ([]DataSource, error) { return s.store.List(ctx) }

// Get returns a single data source (ErrNotFound if missing).
func (s *Service) Get(ctx context.Context, id string) (DataSource, error) {
	return s.store.Get(ctx, id)
}

// Delete removes a data source.
func (s *Service) Delete(ctx context.Context, id string) error { return s.store.Delete(ctx, id) }

// SetEnabled toggles a data source.
func (s *Service) SetEnabled(ctx context.Context, id string, enabled bool) (DataSource, error) {
	return s.store.SetEnabled(ctx, id, enabled)
}

// Status returns the backing mesh status. If the store does not provide status,
// a disconnected status is returned.
func (s *Service) Status(ctx context.Context) (MeshStatus, error) {
	if s.status == nil {
		return MeshStatus{}, nil
	}
	return s.status.Status(ctx)
}
