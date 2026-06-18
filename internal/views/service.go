package views

import (
	"context"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// ValidationError is a user-facing input error.
type ValidationError struct{ Msg string }

func (e ValidationError) Error() string { return e.Msg }

// Service is the application-facing API for saved views.
type Service struct {
	store Store
}

// NewService wires the views service.
func NewService(store Store) *Service { return &Service{store: store} }

// Save creates or updates a view (keyed by ID; a new ID is assigned when empty).
// Owner and Collection are required. If Default is set, any other default for the
// same owner+collection is cleared so at most one default exists.
func (s *Service) Save(ctx context.Context, v View) (View, error) {
	v.Owner = strings.TrimSpace(v.Owner)
	v.Collection = strings.TrimSpace(v.Collection)
	v.Name = strings.TrimSpace(v.Name)
	if v.Owner == "" || v.Collection == "" {
		return View{}, ValidationError{"owner and collection are required"}
	}
	if v.Name == "" {
		return View{}, ValidationError{"a view name is required"}
	}
	if v.ID == "" {
		v.ID = "v" + uuid.NewString()
	}
	if v.Default {
		if err := s.clearDefaults(ctx, v.Owner, v.Collection, v.ID); err != nil {
			return View{}, err
		}
	}
	if err := s.store.PutView(ctx, v); err != nil {
		return View{}, err
	}
	return v, nil
}

// List returns the owner's views for a collection, sorted by name.
func (s *Service) List(ctx context.Context, owner, collection string) ([]View, error) {
	all, err := s.store.ListViews(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0)
	for _, v := range all {
		if v.Owner == owner && v.Collection == collection {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// Default returns the owner's default view for a collection, if any.
func (s *Service) Default(ctx context.Context, owner, collection string) (View, bool, error) {
	list, err := s.List(ctx, owner, collection)
	if err != nil {
		return View{}, false, err
	}
	for _, v := range list {
		if v.Default {
			return v, true, nil
		}
	}
	return View{}, false, nil
}

// SetDefault makes id the owner's default for its collection (clearing others).
// Passing an empty id clears the default for owner+collection.
func (s *Service) SetDefault(ctx context.Context, owner, collection, id string) error {
	if id == "" {
		return s.clearDefaults(ctx, owner, collection, "")
	}
	v, ok, err := s.store.GetView(ctx, id)
	if err != nil {
		return err
	}
	if !ok || v.Owner != owner {
		return ErrNotFound
	}
	if err := s.clearDefaults(ctx, owner, collection, id); err != nil {
		return err
	}
	v.Default = true
	return s.store.PutView(ctx, v)
}

// Delete removes a view the owner owns.
func (s *Service) Delete(ctx context.Context, owner, id string) error {
	v, ok, err := s.store.GetView(ctx, id)
	if err != nil {
		return err
	}
	if !ok || v.Owner != owner {
		return ErrNotFound
	}
	return s.store.DeleteView(ctx, id)
}

// clearDefaults unsets Default on every owner+collection view except keepID.
func (s *Service) clearDefaults(ctx context.Context, owner, collection, keepID string) error {
	list, err := s.List(ctx, owner, collection)
	if err != nil {
		return err
	}
	for _, v := range list {
		if v.ID == keepID || !v.Default {
			continue
		}
		v.Default = false
		if err := s.store.PutView(ctx, v); err != nil {
			return err
		}
	}
	return nil
}
