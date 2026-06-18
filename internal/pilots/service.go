package pilots

import (
	"context"
	"log/slog"

	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
)

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
func (s *Service) Import(ctx context.Context) (int, error) {
	pilots, err := ParseDataset()
	if err != nil {
		return 0, err
	}
	for _, p := range pilots {
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
