package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/awsevidence"
	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/policy"
	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/server"
	"github.com/Adamson-lab/aws-audit-evidence-collector/internal/webhook"
)

func probe(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	awsEndpoint := envOr("AWS_ENDPOINT_URL", "http://localhost:4566")
	awsRegion := envOr("AWS_REGION", "us-east-1")
	bucket := envOr("EVIDENCE_BUCKET", "compliance-audit-evidence")
	opaURL := envOr("OPA_URL", "http://localhost:8181")
	hmacSecret := envOr("WEBHOOK_HMAC_SECRET", "local-dev-audit-secret")
	listenAddr := envOr("LISTEN_ADDR", ":8080")

	ctx := context.Background()
	collector, err := awsevidence.NewCollector(ctx, awsRegion, awsEndpoint, bucket, logger)
	if err != nil {
		logger.Error("failed to initialize aws evidence collector", "error", err)
		os.Exit(1)
	}

	verifier := webhook.NewVerifier(hmacSecret, 5*time.Minute)
	policyClient := policy.NewClient(opaURL, 3*time.Second)

	probeClient := &http.Client{Timeout: 2 * time.Second}
	healthFn := func(pCtx context.Context) (bool, bool) {
		lsOK := probe(pCtx, probeClient, awsEndpoint+"/_localstack/health")
		opaOK := probe(pCtx, probeClient, opaURL+"/health")
		return lsOK, opaOK
	}

	h := server.NewHandler(verifier, policyClient, collector, healthFn, logger)
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           h.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("starting aws-audit-evidence-collector", "addr", listenAddr, "aws_endpoint", awsEndpoint, "opa_url", opaURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info("server shutdown complete")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
