package datasource

import (
	"context"
	"errors"
	"testing"
)

func TestInputValidate(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		ok   bool
	}{
		{"valid", Input{Name: "x", Type: "postgres", Endpoint: "postgres://h"}, true},
		{"empty name", Input{Name: " ", Type: "postgres", Endpoint: "e"}, false},
		{"unknown type", Input{Name: "x", Type: "bogus", Endpoint: "e"}, false},
		{"empty endpoint", Input{Name: "x", Type: "http", Endpoint: ""}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.in.Validate()
			if c.ok && err != nil {
				t.Errorf("expected valid, got %v", err)
			}
			if !c.ok && err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestValidationErrorType(t *testing.T) {
	in := Input{Name: "", Type: "http", Endpoint: "e"}
	err := in.Validate()
	var ve ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
}

func TestServiceCreateValidatesViaMemory(t *testing.T) {
	svc := NewService(NewMemoryStore())
	ctx := context.Background()
	if _, err := svc.Create(ctx, Input{Name: "", Type: "http", Endpoint: "e"}); err == nil {
		t.Error("expected validation error")
	}
	ds, err := svc.Create(ctx, Input{Name: "ok", Type: "http", Endpoint: "http://e", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ds.ID == "" || ds.CreatedAt.IsZero() {
		t.Errorf("created = %+v", ds)
	}
}

func TestMemoryStoreCRUD(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	a, _ := store.Create(ctx, DataSource{Name: "a", Type: "http", Endpoint: "e"})
	_, _ = store.Create(ctx, DataSource{Name: "b", Type: "s3", Endpoint: "e"})

	list, _ := store.List(ctx)
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2", len(list))
	}

	got, err := store.Get(ctx, a.ID)
	if err != nil || got.Name != "a" {
		t.Fatalf("get = %+v, %v", got, err)
	}

	upd, err := store.SetEnabled(ctx, a.ID, false)
	if err != nil || upd.Enabled {
		t.Fatalf("setEnabled = %+v, %v", upd, err)
	}

	if err := store.Delete(ctx, a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v, want ErrNotFound", err)
	}
}
