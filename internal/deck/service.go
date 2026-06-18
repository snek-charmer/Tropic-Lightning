package deck

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ValidationError is a user-facing input error.
type ValidationError struct{ Msg string }

func (e ValidationError) Error() string { return e.Msg }

// Service is the application-facing API for decks and slides.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService wires the deck service.
func NewService(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// CreateDeck creates a named shared deck.
func (s *Service) CreateDeck(ctx context.Context, name, by string) (Deck, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Deck{}, ValidationError{"a deck name is required"}
	}
	d := Deck{ID: "dk" + uuid.NewString(), Name: name, CreatedBy: by, CreatedAt: s.now().Format(time.RFC3339)}
	if err := s.store.PutDeck(ctx, d); err != nil {
		return Deck{}, err
	}
	return d, nil
}

// ListDecks returns all decks.
func (s *Service) ListDecks(ctx context.Context) ([]Deck, error) { return s.store.ListDecks(ctx) }

// GetDeck returns a deck by id.
func (s *Service) GetDeck(ctx context.Context, id string) (Deck, bool, error) {
	return s.store.GetDeck(ctx, id)
}

// DeleteDeck removes a deck and all of its slides.
func (s *Service) DeleteDeck(ctx context.Context, id string) error {
	slides, err := s.Slides(ctx, id)
	if err == nil {
		for _, sl := range slides {
			_ = s.store.DeleteSlide(ctx, sl.ID)
		}
	}
	return s.store.DeleteDeck(ctx, id)
}

// AddSlide publishes a slide to a deck (assigns id + timestamp).
func (s *Service) AddSlide(ctx context.Context, sl Slide) (Slide, error) {
	if sl.DeckID == "" {
		return Slide{}, ValidationError{"a deck is required"}
	}
	if _, ok, err := s.store.GetDeck(ctx, sl.DeckID); err != nil {
		return Slide{}, err
	} else if !ok {
		return Slide{}, ErrNotFound
	}
	sl.Title = strings.TrimSpace(sl.Title)
	if sl.Title == "" {
		sl.Title = strings.TrimSpace(sl.DatasetName)
	}
	if sl.Title == "" {
		sl.Title = "Untitled"
	}
	sl.ID = "sl" + uuid.NewString()
	sl.PublishedAt = s.now().Format(time.RFC3339)
	if err := s.store.PutSlide(ctx, sl); err != nil {
		return Slide{}, err
	}
	return sl, nil
}

// Slides returns a deck's slides, oldest first.
func (s *Service) Slides(ctx context.Context, deckID string) ([]Slide, error) {
	all, err := s.store.ListSlides(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Slide, 0)
	for _, sl := range all {
		if sl.DeckID == deckID {
			out = append(out, sl)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt < out[j].PublishedAt })
	return out, nil
}

// DeleteSlide removes a slide.
func (s *Service) DeleteSlide(ctx context.Context, id string) error {
	return s.store.DeleteSlide(ctx, id)
}
