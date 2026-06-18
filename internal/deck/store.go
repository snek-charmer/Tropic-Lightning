package deck

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	sidecarv1 "github.com/defenseunicorns/keycloak-portal/internal/peat/sidecarv1"
)

const (
	decksCollection  = "decks"
	slidesCollection = "deck_slides"
)

// Store persists decks and slides (source of truth: peat; fake: memory).
type Store interface {
	PutDeck(ctx context.Context, d Deck) error
	GetDeck(ctx context.Context, id string) (Deck, bool, error)
	ListDecks(ctx context.Context) ([]Deck, error)
	DeleteDeck(ctx context.Context, id string) error

	PutSlide(ctx context.Context, s Slide) error
	ListSlides(ctx context.Context) ([]Slide, error)
	DeleteSlide(ctx context.Context, id string) error
}

// PeatStore persists decks/slides in the peat mesh.
type PeatStore struct {
	conn   *grpc.ClientConn
	client sidecarv1.PeatSidecarClient
}

// NewPeatStore dials the peat sidecar at addr. tlsCreds may be nil (plaintext).
func NewPeatStore(addr string, tlsCreds credentials.TransportCredentials) (*PeatStore, error) {
	creds := tlsCreds
	if creds == nil {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dialing peat node %q: %w", addr, err)
	}
	return &PeatStore{conn: conn, client: sidecarv1.NewPeatSidecarClient(conn)}, nil
}

// Close releases the gRPC connection.
func (s *PeatStore) Close() error { return s.conn.Close() }

func (s *PeatStore) put(ctx context.Context, collection, id string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.client.PutDocument(ctx, &sidecarv1.PutDocumentRequest{Collection: collection, DocId: id, JsonData: string(data)})
	if err != nil {
		return fmt.Errorf("peat PutDocument(%s/%s): %w", collection, id, err)
	}
	return nil
}

func (s *PeatStore) del(ctx context.Context, collection, id string) error {
	_, err := s.client.DeleteDocument(ctx, &sidecarv1.DeleteDocumentRequest{Collection: collection, DocId: id})
	if err != nil {
		return fmt.Errorf("peat DeleteDocument(%s/%s): %w", collection, id, err)
	}
	return nil
}

func (s *PeatStore) PutDeck(ctx context.Context, d Deck) error {
	return s.put(ctx, decksCollection, d.ID, d)
}

func (s *PeatStore) GetDeck(ctx context.Context, id string) (Deck, bool, error) {
	got, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{Collection: decksCollection, DocId: id})
	if err != nil {
		return Deck{}, false, fmt.Errorf("peat GetDocument(%s/%s): %w", decksCollection, id, err)
	}
	if got.JsonData == nil {
		return Deck{}, false, nil
	}
	var d Deck
	if err := json.Unmarshal([]byte(*got.JsonData), &d); err != nil {
		return Deck{}, false, err
	}
	return d, true, nil
}

func (s *PeatStore) ListDecks(ctx context.Context) ([]Deck, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: decksCollection})
	if err != nil {
		return nil, fmt.Errorf("peat ListDocuments(%s): %w", decksCollection, err)
	}
	ids := append([]string(nil), resp.DocIds...)
	sort.Strings(ids)
	out := make([]Deck, 0, len(ids))
	for _, id := range ids {
		d, ok, err := s.GetDeck(ctx, id)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *PeatStore) DeleteDeck(ctx context.Context, id string) error {
	return s.del(ctx, decksCollection, id)
}

func (s *PeatStore) PutSlide(ctx context.Context, sl Slide) error {
	return s.put(ctx, slidesCollection, sl.ID, sl)
}

func (s *PeatStore) ListSlides(ctx context.Context) ([]Slide, error) {
	resp, err := s.client.ListDocuments(ctx, &sidecarv1.ListDocumentsRequest{Collection: slidesCollection})
	if err != nil {
		return nil, fmt.Errorf("peat ListDocuments(%s): %w", slidesCollection, err)
	}
	ids := append([]string(nil), resp.DocIds...)
	sort.Strings(ids)
	out := make([]Slide, 0, len(ids))
	for _, id := range ids {
		got, err := s.client.GetDocument(ctx, &sidecarv1.GetDocumentRequest{Collection: slidesCollection, DocId: id})
		if err != nil {
			return nil, fmt.Errorf("peat GetDocument(%s): %w", id, err)
		}
		if got.JsonData == nil {
			continue
		}
		var sl Slide
		if err := json.Unmarshal([]byte(*got.JsonData), &sl); err != nil {
			return nil, err
		}
		out = append(out, sl)
	}
	return out, nil
}

func (s *PeatStore) DeleteSlide(ctx context.Context, id string) error {
	return s.del(ctx, slidesCollection, id)
}

// MemoryStore is an in-memory deck store for tests and no-peat runs.
type MemoryStore struct {
	mu     sync.Mutex
	decks  map[string]Deck
	slides map[string]Slide
}

// NewMemoryStore returns an empty in-memory deck store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{decks: map[string]Deck{}, slides: map[string]Slide{}}
}

func (m *MemoryStore) PutDeck(_ context.Context, d Deck) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decks[d.ID] = d
	return nil
}

func (m *MemoryStore) GetDeck(_ context.Context, id string) (Deck, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.decks[id]
	return d, ok, nil
}

func (m *MemoryStore) ListDecks(_ context.Context) ([]Deck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Deck, 0, len(m.decks))
	for _, d := range m.decks {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) DeleteDeck(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.decks, id)
	return nil
}

func (m *MemoryStore) PutSlide(_ context.Context, sl Slide) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slides[sl.ID] = sl
	return nil
}

func (m *MemoryStore) ListSlides(_ context.Context) ([]Slide, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Slide, 0, len(m.slides))
	for _, sl := range m.slides {
		out = append(out, sl)
	}
	return out, nil
}

func (m *MemoryStore) DeleteSlide(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.slides, id)
	return nil
}
