package operators

import (
	"context"
	"testing"
)

func TestOperatorCRUD(t *testing.T) {
	svc := NewService(NewMemoryStore())
	ctx := context.Background()

	if _, err := svc.CreateOperator(ctx, "  ", ""); err == nil {
		t.Error("expected error for blank username")
	}
	o, err := svc.CreateOperator(ctx, "s1", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if o.DisplayName != "s1" { // defaults to username
		t.Errorf("display = %q", o.DisplayName)
	}
	ops, _ := svc.ListOperators(ctx)
	if len(ops) != 1 {
		t.Fatalf("operators = %d", len(ops))
	}
}

func TestAssignmentAndAccess(t *testing.T) {
	svc := NewService(NewMemoryStore())
	ctx := context.Background()
	_, _ = svc.CreateOperator(ctx, "s1", "Op One")
	_, _ = svc.CreateOperator(ctx, "s2", "Op Two")
	_ = svc.RegisterDataset(ctx, "pilots", "USAF Pilots", KindPilots, "pilots")
	_ = svc.RegisterDataset(ctx, "ds_roster", "Roster", KindGeneric, "ds_roster")

	if svc.IsAssigned(ctx, "pilots", "s1") {
		t.Error("s1 should not be assigned yet")
	}
	_ = svc.SetAssignments(ctx, "pilots", []string{"s1"})
	if !svc.IsAssigned(ctx, "pilots", "s1") {
		t.Error("s1 should be assigned to pilots")
	}
	if svc.IsAssigned(ctx, "pilots", "s2") {
		t.Error("s2 should not be assigned")
	}

	mine, _ := svc.DatasetsForOperator(ctx, "s1")
	if len(mine) != 1 || mine[0].Key != "pilots" {
		t.Errorf("s1 datasets = %+v", mine)
	}

	// RegisterDataset is idempotent and preserves assignments.
	_ = svc.RegisterDataset(ctx, "pilots", "USAF Pilots (v2)", KindPilots, "pilots")
	if !svc.IsAssigned(ctx, "pilots", "s1") {
		t.Error("re-register should preserve assignment")
	}

	// Deleting an operator removes them from assignments.
	_ = svc.DeleteOperator(ctx, "s1")
	if svc.IsAssigned(ctx, "pilots", "s1") {
		t.Error("deleted operator should be unassigned")
	}
}
