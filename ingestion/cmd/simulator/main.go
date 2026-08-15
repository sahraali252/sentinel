package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/sahraali252/sentinel/ingestion/internal/publisher"
	"github.com/sahraali252/sentinel/ingestion/internal/simulator"
)

type config struct {
	brokers, topic, mode                    string
	rate, count, attackEvery, spikeMultiple int
	seed                                    int64
	maxBuffered                             int
}

func main() {
	cfg := readConfig()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	mode, err := simulator.ParseMode(cfg.mode)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	producer, err := publisher.NewKafka(cfg.brokers, cfg.topic, cfg.maxBuffered, logger)
	if err != nil {
		logger.Error("producer initialization failed", "error", err)
		os.Exit(1)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = producer.Ping(pingCtx)
	cancel()
	if err != nil {
		logger.Error("Kafka unavailable", "error", err)
		os.Exit(1)
	}
	generator := simulator.New(cfg.seed)
	logger.Info("traffic simulator started", "topic", cfg.topic, "mode", mode, "events_per_second", cfg.rate, "count", cfg.count)
	ticker := time.NewTicker(time.Second / time.Duration(cfg.rate))
	defer ticker.Stop()
	produced := 0
	for cfg.count == 0 || produced < cfg.count {
		select {
		case <-ctx.Done():
			logger.Info("shutdown requested", "produced", produced)
			closeProducer(producer, logger)
			return
		case <-ticker.C:
			burst := 1
			if mode == simulator.Spike {
				burst = cfg.spikeMultiple
			}
			for i := 0; i < burst && (cfg.count == 0 || produced < cfg.count); i++ {
				produced++
				e := generator.Next(mode, produced, cfg.attackEvery)
				if err := producer.Publish(ctx, e); err != nil {
					logger.Error("event publish failed", "event_id", e.ID, "error", err)
					continue
				}
				if produced%cfg.rate == 0 {
					logger.Info("traffic produced", "total", produced, "latest_scenario", e.Scenario)
				}
			}
		}
	}
	logger.Info("requested event count produced", "produced", produced)
	closeProducer(producer, logger)
}

func readConfig() config {
	cfg := config{}
	flag.StringVar(&cfg.brokers, "brokers", envOr("KAFKA_BROKERS", "kafka:9092"), "comma-separated Kafka brokers")
	flag.StringVar(&cfg.topic, "topic", envOr("KAFKA_TOPIC_RAW_EVENTS", "raw-events"), "Kafka topic")
	flag.StringVar(&cfg.mode, "mode", envOr("SIMULATOR_MODE", "mixed"), "normal, credential-stuffing, scraping, injection, spike, or mixed")
	flag.IntVar(&cfg.rate, "rate", envInt("SIMULATOR_RATE", 25), "base events per second")
	flag.IntVar(&cfg.count, "count", envInt("SIMULATOR_COUNT", 0), "events to produce; zero runs continuously")
	flag.IntVar(&cfg.attackEvery, "attack-every", envInt("SIMULATOR_ATTACK_EVERY", 40), "mixed-mode interval between malicious events")
	flag.IntVar(&cfg.spikeMultiple, "spike-multiple", envInt("SIMULATOR_SPIKE_MULTIPLE", 10), "spike-mode burst size per base tick")
	flag.Int64Var(&cfg.seed, "seed", envInt64("SIMULATOR_SEED", time.Now().UnixNano()), "pseudo-random seed")
	flag.IntVar(&cfg.maxBuffered, "max-buffered", envInt("SIMULATOR_MAX_BUFFERED", 10_000), "maximum queued Kafka records")
	flag.Parse()
	if cfg.rate <= 0 || cfg.attackEvery <= 0 || cfg.spikeMultiple <= 0 || cfg.maxBuffered <= 0 || cfg.count < 0 {
		fmt.Fprintln(os.Stderr, "rate, attack-every, spike-multiple, and max-buffered must be positive; count must be non-negative")
		os.Exit(2)
	}
	return cfg
}

func closeProducer(producer *publisher.Kafka, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := producer.Close(ctx); err != nil {
		logger.Error("producer shutdown incomplete", "error", err)
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
func envInt64(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(envOr(key, strconv.FormatInt(fallback, 10)), 10, 64)
	if err != nil {
		return fallback
	}
	return value
}
