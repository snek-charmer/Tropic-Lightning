package pilots

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
)

// Summary is the readiness rollup powering the operator status wheel.
type Summary struct {
	Total     int `json:"total"`
	Available int `json:"available"`
	Grounded  int `json:"grounded"`
}

// AvailablePct returns the available share as a 0–100 integer.
func (s Summary) AvailablePct() int {
	if s.Total == 0 {
		return 0
	}
	return int(float64(s.Available)/float64(s.Total)*100 + 0.5)
}

const (
	catalogName   = "USAF Pilots (MHS Genesis synthetic)"
	datasetSource = "https://github.com/DHA-CDAO-API/ndia_hackathon"
)

// Service ingests the embedded pilots dataset into the peat mesh and exposes it
// for reading. Importing also registers a data-source catalog entry so the
// dataset shows up alongside other connections.
type Service struct {
	store   Store
	catalog *datasource.Service // optional: registers the catalog entry
	log     *slog.Logger
}

// NewService wires the pilots service. catalog may be nil to skip the catalog
// entry; log may be nil.
func NewService(store Store, catalog *datasource.Service, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: store, catalog: catalog, log: log}
}

// Import parses the embedded dataset, writes every pilot into the store (peat),
// and registers the catalog entry. Returns the number of pilots imported.
// Operator-set mission status is preserved across re-imports.
func (s *Service) Import(ctx context.Context) (int, error) {
	pilots, err := ParseDataset()
	if err != nil {
		return 0, err
	}

	// Preserve operator edits: keep mission status for pilots a user has touched.
	existing := map[string]Pilot{}
	if cur, err := s.store.List(ctx); err == nil {
		for _, p := range cur {
			existing[p.PilotID] = p
		}
	}

	for _, p := range pilots {
		if prev, ok := existing[p.PilotID]; ok && prev.StatusBy != "" {
			p.MissionStatus = prev.MissionStatus
			p.StatusNote = prev.StatusNote
			p.StatusBy = prev.StatusBy
			p.StatusAt = prev.StatusAt
		}
		if err := s.store.Put(ctx, p); err != nil {
			return 0, err
		}
	}
	// Catalog registration is best-effort — the data is already ingested.
	if s.catalog != nil {
		if err := s.ensureCatalog(ctx); err != nil {
			s.log.Warn("registering pilots data-source catalog entry", "err", err)
		}
	}
	return len(pilots), nil
}

// List returns all ingested pilots.
func (s *Service) List(ctx context.Context) ([]Pilot, error) { return s.store.List(ctx) }

// Count returns how many pilots are stored.
func (s *Service) Count(ctx context.Context) (int, error) { return s.store.Count(ctx) }

// SetStatus updates a pilot's mission availability (operator action). status
// must be "available" or "grounded"; by records who made the change.
func (s *Service) SetStatus(ctx context.Context, id, status, note, by string) (Pilot, error) {
	if status != StatusAvailable && status != StatusGrounded {
		return Pilot{}, fmt.Errorf("invalid status %q (want %q or %q)", status, StatusAvailable, StatusGrounded)
	}
	p, err := s.store.Get(ctx, id)
	if err != nil {
		return Pilot{}, err
	}
	p.MissionStatus = status
	p.StatusNote = note
	p.StatusBy = by
	p.StatusAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.store.Put(ctx, p); err != nil {
		return Pilot{}, err
	}
	return p, nil
}

// ReadinessSummary rolls up availability for the status wheel.
func (s *Service) ReadinessSummary(ctx context.Context) (Summary, error) {
	all, err := s.store.List(ctx)
	if err != nil {
		return Summary{}, err
	}
	sum := Summary{Total: len(all)}
	for _, p := range all {
		if p.Available() {
			sum.Available++
		} else {
			sum.Grounded++
		}
	}
	return sum, nil
}

// ensureCatalog creates the data-source catalog entry once (idempotent by name).
func (s *Service) ensureCatalog(ctx context.Context) error {
	existing, err := s.catalog.List(ctx)
	if err != nil {
		return err
	}
	for _, d := range existing {
		if d.Name == catalogName {
			return nil
		}
	}
	_, err = s.catalog.Create(ctx, datasource.Input{
		Name:     catalogName,
		Type:     "file",
		Endpoint: datasetSource,
		Enabled:  true,
	})
	return err
}
