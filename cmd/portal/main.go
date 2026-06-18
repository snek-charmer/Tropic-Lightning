package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/defenseunicorns/keycloak-portal/internal/auth"
	"github.com/defenseunicorns/keycloak-portal/internal/config"
	"github.com/defenseunicorns/keycloak-portal/internal/dataset"
	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
	"github.com/defenseunicorns/keycloak-portal/internal/operators"
	"github.com/defenseunicorns/keycloak-portal/internal/pilots"
	"github.com/defenseunicorns/keycloak-portal/internal/web"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Bound the discovery call so a misconfigured issuer fails fast.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	authn, err := auth.NewAuthenticator(ctx, cfg)
	if err != nil {
		return err
	}

	// Data sources are stored in the local peat node: a CRDT mesh datastore that
	// works disconnected and reconciles across the mesh on reconnect.
	var creds credentials.TransportCredentials
	if cfg.PeatTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	store, err := datasource.NewPeatStore(cfg.PeatNodeAddr, cfg.PeatCollection, creds)
	if err != nil {
		return err
	}
	defer store.Close()
	slog.Info("data sources backed by peat node", "addr", cfg.PeatNodeAddr, "collection", cfg.PeatCollection, "tls", cfg.PeatTLS)

	// Best-effort status probe so startup logs reflect mesh reachability (not
	// fatal — the co-located node may come up slightly later).
	if st, err := store.Status(ctx); err != nil {
		slog.Warn("peat node not reachable yet", "err", err)
	} else {
		slog.Info("peat node reachable", "node_id", st.NodeID, "sync_active", st.SyncActive, "peers", st.ConnectedPeers)
	}

	dsService := datasource.NewService(store)

	// Pilots dataset, ingested into a separate peat collection on the same node.
	pilotStore, err := pilots.NewPeatStore(cfg.PeatNodeAddr, creds)
	if err != nil {
		return err
	}
	defer pilotStore.Close()
	pilotService := pilots.NewService(pilotStore, dsService, slog.Default())

	// Uploaded files become generic datasets in their own peat collections.
	datasetStore, err := dataset.NewPeatStore(cfg.PeatNodeAddr, creds)
	if err != nil {
		return err
	}
	defer datasetStore.Close()
	datasetService := dataset.NewService(datasetStore, dsService, slog.Default())

	// Operator registry + dataset assignments.
	operatorStore, err := operators.NewPeatStore(cfg.PeatNodeAddr, creds)
	if err != nil {
		return err
	}
	defer operatorStore.Close()
	operatorService := operators.NewService(operatorStore)
	// Make the pilots dataset assignable even before it's (re)imported (best-effort).
	regCtx, regCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := operatorService.RegisterDataset(regCtx, "pilots", "USAF Pilots", operators.KindPilots, "pilots"); err != nil {
		slog.Warn("registering pilots dataset", "err", err)
	}
	regCancel()

	srv, err := web.NewServer(authn, cfg, dsService, pilotService, datasetService, operatorService)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("starting server", "addr", cfg.ListenAddr, "issuer", cfg.Issuer)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			stop()
		}
	}()

	<-shutdownCtx.Done()
	slog.Info("shutting down")

	stopCtx, cancelStop := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStop()
	return httpServer.Shutdown(stopCtx)
}
