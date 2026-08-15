package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sahraali252/sentinel/detector/internal/alerts"
	"github.com/sahraali252/sentinel/detector/internal/config"
	"github.com/sahraali252/sentinel/detector/internal/consumer"
	"github.com/sahraali252/sentinel/detector/internal/detection/anomaly"
	"github.com/sahraali252/sentinel/detector/internal/detection/pattern"
	"github.com/sahraali252/sentinel/detector/internal/detection/ratelimit"
	"github.com/sahraali252/sentinel/detector/internal/detection/window"
	"github.com/sahraali252/sentinel/detector/internal/engine"
	"github.com/sahraali252/sentinel/detector/internal/store"
	"github.com/sahraali252/sentinel/detector/internal/whitelist"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "check the local detector health endpoint")
	flag.Parse()
	if *healthcheck {
		runHealthcheck()
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rules, err := config.Load(envOr("DETECTOR_RULES_PATH", "/config/rules.yaml"))
	fatalIf(logger, err, "load detector rules")
	allowlist, err := whitelist.New(rules.Whitelist)
	fatalIf(logger, err, "compile whitelist")
	redisClient := redis.NewClient(&redis.Options{Addr: envOr("REDIS_ADDR", "redis:6379"), Password: os.Getenv("REDIS_PASSWORD"), DB: envInt("REDIS_DB", 0)})
	defer redisClient.Close()
	fatalIf(logger, redisClient.Ping(ctx).Err(), "connect Redis")
	postgres, err := store.NewPostgres(ctx, envOr("POSTGRES_DSN", "postgres://sentinel:sentinel_dev@postgres:5432/sentinel?sslmode=disable"))
	fatalIf(logger, err, "connect Postgres")
	defer postgres.Close()
	fatalIf(logger, postgres.EnsureSchema(ctx), "prepare alert schema")
	hub := alerts.NewHub(logger)
	rateDetector := ratelimit.New(window.NewRedisCounter(redisClient, "detect:rate"), rules.RateLimit.Requests, rules.RateLimit.Window, rules.RateLimit.Severity)
	anomalyDetector := anomaly.New(anomaly.NewRedisStore(redisClient, "detect:ewma"), rules.Anomaly.Alpha, rules.Anomaly.ZThreshold, rules.Anomaly.MinimumSamples, rules.Anomaly.StateTTL, rules.Anomaly.Severity)
	patternDetector := pattern.New(window.NewRedisCounter(redisClient, "detect:auth401"), redisClient, pattern.Options{Failures: rules.Credential.Failures, FailureWindow: rules.Credential.Window, SequenceLength: rules.Scraping.SequenceLength, MaxIDGap: rules.Scraping.MaxIDGap, ScrapeTTL: rules.Scraping.StateTTL, CredentialSeverity: rules.Credential.Severity, ScrapingSeverity: rules.Scraping.Severity, SignatureSeverity: rules.Signatures.Severity, CredentialEnabled: rules.Credential.Enabled, ScrapingEnabled: rules.Scraping.Enabled, SignaturesEnabled: rules.Signatures.Enabled})
	detectionEngine := engine.New(rateDetector, anomalyDetector, patternDetector, allowlist, postgres, hub, rules.RateLimit.Enabled, rules.Anomaly.Enabled)
	kafkaConsumer, err := consumer.New(splitCSV(envOr("KAFKA_BROKERS", "kafka:9092")), envOr("KAFKA_TOPIC_RAW_EVENTS", "raw-events"), envOr("KAFKA_CONSUMER_GROUP", "sentinel-detectors"), envInt("DETECTOR_BATCH_SIZE", 500), int64(envInt("DETECTOR_LAG_WARNING", 5000)), detectionEngine, logger)
	fatalIf(logger, err, "create Kafka consumer")
	defer kafkaConsumer.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = kafkaConsumer.Ping(pingCtx)
	cancel()
	fatalIf(logger, err, "connect Kafka")
	server := newHTTPServer(envOr("DETECTOR_HTTP_ADDR", ":8080"), hub, rules, postgres)
	go func() {
		logger.Info("detector API ready", "address", server.Addr, "phase", 3)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server stopped", "error", err)
			stop()
		}
	}()
	logger.Info("detection engine started", "group", envOr("KAFKA_CONSUMER_GROUP", "sentinel-detectors"), "batch_size", envInt("DETECTOR_BATCH_SIZE", 500))
	if err := kafkaConsumer.Run(ctx); err != nil {
		logger.Error("consumer stopped", "error", err)
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}

func newHTTPServer(addr string, hub *alerts.Hub, rules config.Config, postgres *store.Postgres) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"service": "sentinel-detector", "status": "ready", "version": "1.0.0"})
	})
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, rules) })
	mux.HandleFunc("GET /api/alerts", func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if value, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && value > 0 {
			limit = value
		}
		items, err := postgres.ListAlerts(r.Context(), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load alerts"})
			return
		}
		writeJSON(w, http.StatusOK, items)
	})
	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) {
		summary, err := postgres.AlertSummary(r.Context(), time.Now().UTC().Add(-24*time.Hour))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load summary"})
			return
		}
		writeJSON(w, http.StatusOK, summary)
	})
	mux.Handle("GET /ws", hub)
	return &http.Server{Addr: addr, Handler: withCORS(mux), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
}
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func runHealthcheck() {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:8080/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	_ = resp.Body.Close()
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fatalIf(logger *slog.Logger, err error, message string) {
	if err != nil {
		logger.Error(message, "error", err)
		os.Exit(1)
	}
}
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(envOr(key, strconv.Itoa(fallback)))
	if err != nil {
		return fallback
	}
	return value
}
func splitCSV(value string) []string {
	fields := strings.Split(value, ",")
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
