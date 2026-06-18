package operators

import (
	"context"
	"strings"
	"time"
)

// ValidationError is a user-facing input error.
type ValidationError struct{ Msg string }

func (e ValidationError) Error() string { return e.Msg }

// Service is the application-facing API for operators and assignments.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService wires the operators service.
func NewService(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// CreateOperator registers (or updates) an operator by username.
func (s *Service) CreateOperator(ctx context.Context, username, display string) (Operator, error) {
	username = strings.TrimSpace(username)
	display = strings.TrimSpace(display)
	if username == "" {
		return Operator{}, ValidationError{"username is required"}
	}
	if display == "" {
		display = username
	}
	o := Operator{Username: username, DisplayName: display, CreatedAt: s.now().Format(time.RFC3339)}
	if err := s.store.PutOperator(ctx, o); err != nil {
		return Operator{}, err
	}
	return o, nil
}

// ListOperators returns all operators.
func (s *Service) ListOperators(ctx context.Context) ([]Operator, error) {
	return s.store.ListOperators(ctx)
}

// DeleteOperator removes an operator and clears them from all assignments.
func (s *Service) DeleteOperator(ctx context.Context, username string) error {
	if err := s.store.DeleteOperator(ctx, username); err != nil {
		return err
	}
	sets, err := s.store.ListDatasets(ctx)
	if err != nil {
		return err
	}
	for _, d := range sets {
		if !d.AssignedToUser(username) {
			continue
		}
		kept := d.AssignedTo[:0]
		for _, u := range d.AssignedTo {
			if u != username {
				kept = append(kept, u)
			}
		}
		d.AssignedTo = kept
		if err := s.store.PutDataset(ctx, d); err != nil {
			return err
		}
	}
	return nil
}

// RegisterDataset records a dataset (idempotent), preserving existing
// assignments and refreshing the display name.
func (s *Service) RegisterDataset(ctx context.Context, key, name, kind, collection string) error {
	d := Dataset{Key: key, Name: name, Kind: kind, Collection: collection}
	if existing, err := s.store.GetDataset(ctx, key); err == nil {
		d.AssignedTo = existing.AssignedTo
	}
	return s.store.PutDataset(ctx, d)
}

// SetAssignments replaces the operator list for a dataset.
func (s *Service) SetAssignments(ctx context.Context, key string, usernames []string) error {
	d, err := s.store.GetDataset(ctx, key)
	if err != nil {
		return err
	}
	d.AssignedTo = usernames
	return s.store.PutDataset(ctx, d)
}

// ListDatasets returns all registered datasets.
func (s *Service) ListDatasets(ctx context.Context) ([]Dataset, error) {
	return s.store.ListDatasets(ctx)
}

// DatasetsForOperator returns datasets assigned to username.
func (s *Service) DatasetsForOperator(ctx context.Context, username string) ([]Dataset, error) {
	all, err := s.store.ListDatasets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Dataset, 0, len(all))
	for _, d := range all {
		if d.AssignedToUser(username) {
			out = append(out, d)
		}
	}
	return out, nil
}

// IsAssigned reports whether username may access the dataset key.
func (s *Service) IsAssigned(ctx context.Context, key, username string) bool {
	d, err := s.store.GetDataset(ctx, key)
	if err != nil {
		return false
	}
	return d.AssignedToUser(username)
}
