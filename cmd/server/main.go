// Command server starts the CoverOnes gateway service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CoverOnes/gateway/internal/auth/jwks"
	"github.com/CoverOnes/gateway/internal/config"
	"github.com/CoverOnes/gateway/internal/handler"
	"github.com/CoverOnes/gateway/internal/platform/logger"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "perform a liveness check against /healthz and exit 0/1")
	flag.Parse()

	// Docker HEALTHCHECK mode: GET /healthz and exit immediately.
	if *healthcheck {
		if err := runHealthCheck(); err != nil {
			slog.Error("healthcheck failed", "err", err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	if err := run(); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

// runHealthCheck issues a GET to the local /healthz endpoint.
// It reads PORT from the GATEWAY_PORT environment variable (default 8080).
func runHealthCheck() error {
	port := os.Getenv("GATEWAY_PORT")
	if port == "" {
		port = "8080"
	}

	url := fmt.Sprintf("http://127.0.0.1:%s/healthz", port)

	client := &http.Client{Timeout: 2 * time.Second}

	resp, err := client.Get(url) //nolint:noctx // healthcheck is a one-shot process; no request context needed
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}

	defer resp.Body.Close() //nolint:errcheck // best-effort close on healthcheck response

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	return nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Logger — JSON to stdout.
	log := logger.New(cfg.LogLevel)
	slog.SetDefault(log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// JWKS cache — fetches user service public keys at boot and refreshes on TTL.
	jwksTTL := time.Duration(cfg.JWKSCacheTTLSec) * time.Second
	jwksFetchTimeout := time.Duration(cfg.JWKSFetchTimeout) * time.Second
	cache := jwks.NewCache(cfg.JWKSUserURL, jwksTTL, jwksFetchTimeout)
	cache.Start(ctx)

	slog.Info("JWKS cache started", "url", cfg.JWKSUserURL, "ttl_sec", cfg.JWKSCacheTTLSec)

	// Router.
	r, err := handler.NewRouterFromConfig(cfg, cache)
	if err != nil {
		return fmt.Errorf("build router: %w", err)
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second, // mitigate slow-loris header attacks
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("gateway starting", "addr", srv.Addr)

		if listenErr := srv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			slog.Error("server listen error", "err", listenErr)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("shutting down gracefully")

	cancel() // stop JWKS refresh loop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
		return fmt.Errorf("server shutdown: %w", shutdownErr)
	}

	slog.Info("gateway stopped")

	return nil
}
