package deck

import (
	"context"
	"testing"
)

func TestDeckSlidesLifecycle(t *testing.T) {
	svc := NewService(NewMemoryStore())
	ctx := context.Background()

	d, err := svc.CreateDeck(ctx, "Sync", "alice")
	if err != nil || d.ID == "" {
		t.Fatalf("create deck: %v", err)
	}
	a, err := svc.AddSlide(ctx, Slide{DeckID: d.ID, Title: "A", Collection: "ds_x", ViewType: "bar", PublishedBy: "alice"})
	if err != nil {
		t.Fatalf("add slide: %v", err)
	}
	if a.ID == "" || a.PublishedAt == "" {
		t.Error("slide should get an id + timestamp")
	}
	_, _ = svc.AddSlide(ctx, Slide{DeckID: d.ID, Title: "B", Collection: "ds_y", PublishedBy: "bob"})

	slides, _ := svc.Slides(ctx, d.ID)
	if len(slides) != 2 {
		t.Fatalf("slides = %d, want 2", len(slides))
	}
	// Slides are scoped to their deck.
	other, _ := svc.CreateDeck(ctx, "Other", "x")
	if s2, _ := svc.Slides(ctx, other.ID); len(s2) != 0 {
		t.Errorf("other deck should have 0 slides, got %d", len(s2))
	}

	// Deleting a slide.
	if err := svc.DeleteSlide(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if slides, _ := svc.Slides(ctx, d.ID); len(slides) != 1 {
		t.Errorf("after slide delete = %d, want 1", len(slides))
	}

	// Deleting the deck removes its remaining slides.
	if err := svc.DeleteDeck(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := svc.GetDeck(ctx, d.ID); ok {
		t.Error("deck should be gone")
	}
	if slides, _ := svc.Slides(ctx, d.ID); len(slides) != 0 {
		t.Errorf("deck delete should remove its slides, got %d", len(slides))
	}
}

func TestAddSlideValidation(t *testing.T) {
	svc := NewService(NewMemoryStore())
	ctx := context.Background()
	if _, err := svc.AddSlide(ctx, Slide{Title: "x"}); err == nil {
		t.Error("expected error for missing deck")
	}
	if _, err := svc.AddSlide(ctx, Slide{DeckID: "nope", Title: "x"}); err != ErrNotFound {
		t.Errorf("missing deck = %v, want ErrNotFound", err)
	}
	if _, err := svc.CreateDeck(ctx, "  ", "a"); err == nil {
		t.Error("expected error for blank deck name")
	}
}
