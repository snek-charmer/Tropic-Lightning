package views

import (
	"context"
	"testing"
)

func TestSaveListDefault(t *testing.T) {
	svc := NewService(NewMemoryStore())
	ctx := context.Background()

	a, err := svc.Save(ctx, View{Owner: "s1", Collection: "ds_x", Name: "Grounded", FilterCol: "status", FilterVal: "down", Default: true})
	if err != nil {
		t.Fatalf("save a: %v", err)
	}
	if a.ID == "" {
		t.Fatal("expected an assigned ID")
	}
	b, err := svc.Save(ctx, View{Owner: "s1", Collection: "ds_x", Name: "Hill", FilterCol: "base", FilterVal: "Hill", Default: true})
	if err != nil {
		t.Fatalf("save b: %v", err)
	}

	// Only one default per (owner, collection): b is now default, a is not.
	def, ok, err := svc.Default(ctx, "s1", "ds_x")
	if err != nil || !ok {
		t.Fatalf("default: %v ok=%v", err, ok)
	}
	if def.ID != b.ID {
		t.Errorf("default = %s, want b (%s)", def.ID, b.ID)
	}

	// Views are private to the owner.
	list, _ := svc.List(ctx, "s1", "ds_x")
	if len(list) != 2 {
		t.Errorf("s1 views = %d, want 2", len(list))
	}
	if other, _ := svc.List(ctx, "s2", "ds_x"); len(other) != 0 {
		t.Errorf("s2 should see no views, got %d", len(other))
	}

	// SetDefault to a, then clear it.
	if err := svc.SetDefault(ctx, "s1", "ds_x", a.ID); err != nil {
		t.Fatalf("set default a: %v", err)
	}
	if def, _, _ := svc.Default(ctx, "s1", "ds_x"); def.ID != a.ID {
		t.Errorf("default should be a after SetDefault")
	}
	if err := svc.SetDefault(ctx, "s1", "ds_x", ""); err != nil {
		t.Fatalf("clear default: %v", err)
	}
	if _, ok, _ := svc.Default(ctx, "s1", "ds_x"); ok {
		t.Error("default should be cleared")
	}
}

func TestDeleteOwnershipEnforced(t *testing.T) {
	svc := NewService(NewMemoryStore())
	ctx := context.Background()
	v, _ := svc.Save(ctx, View{Owner: "s1", Collection: "ds_x", Name: "Mine"})

	// A different user cannot delete it.
	if err := svc.Delete(ctx, "s2", v.ID); err != ErrNotFound {
		t.Errorf("cross-user delete = %v, want ErrNotFound", err)
	}
	if err := svc.Delete(ctx, "s1", v.ID); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if list, _ := svc.List(ctx, "s1", "ds_x"); len(list) != 0 {
		t.Errorf("views after delete = %d, want 0", len(list))
	}
}

func TestSaveValidation(t *testing.T) {
	svc := NewService(NewMemoryStore())
	ctx := context.Background()
	if _, err := svc.Save(ctx, View{Owner: "s1", Collection: "ds_x"}); err == nil {
		t.Error("expected error for empty name")
	}
	if _, err := svc.Save(ctx, View{Owner: "", Collection: "ds_x", Name: "x"}); err == nil {
		t.Error("expected error for empty owner")
	}
}
