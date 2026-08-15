package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/sahraali252/sentinel/ingestion/internal/event"
	"github.com/twmb/franz-go/pkg/kgo"
)

type Kafka struct {
	client *kgo.Client
	topic  string
	log    *slog.Logger
}

func NewKafka(brokers, topic string, maxBuffered int, logger *slog.Logger) (*Kafka, error) {
	client, err := kgo.NewClient(kgo.SeedBrokers(splitBrokers(brokers)...), kgo.DefaultProduceTopic(topic), kgo.RecordPartitioner(kgo.StickyKeyPartitioner(nil)), kgo.RequiredAcks(kgo.AllISRAcks()), kgo.ProducerBatchMaxBytes(1_048_576), kgo.ProducerLinger(20*time.Millisecond), kgo.MaxBufferedRecords(maxBuffered))
	if err != nil {
		return nil, fmt.Errorf("create Kafka producer: %w", err)
	}
	return &Kafka{client: client, topic: topic, log: logger}, nil
}

func (k *Kafka) Ping(ctx context.Context) error {
	if err := k.client.Ping(ctx); err != nil {
		return fmt.Errorf("ping Kafka: %w", err)
	}
	return nil
}

func (k *Kafka) Publish(ctx context.Context, request event.APIRequest) error {
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	// The source IP key preserves per-client ordering for stateful detectors.
	record := &kgo.Record{Topic: k.topic, Key: []byte(request.SourceIP), Value: payload, Headers: []kgo.RecordHeader{{Key: "schema-version", Value: []byte("1")}, {Key: "scenario", Value: []byte(request.Scenario)}}}
	// Produce blocks when the bounded buffer fills: backpressure, never silent loss.
	k.client.Produce(ctx, record, func(_ *kgo.Record, produceErr error) {
		if produceErr != nil {
			k.log.Error("event delivery failed", "event_id", request.ID, "source_ip", request.SourceIP, "error", produceErr)
		}
	})
	return nil
}

func (k *Kafka) Close(ctx context.Context) error {
	if err := k.client.Flush(ctx); err != nil {
		return fmt.Errorf("flush Kafka producer: %w", err)
	}
	k.client.Close()
	return nil
}

func splitBrokers(raw string) []string {
	parts := strings.Split(raw, ",")
	brokers := make([]string, 0, len(parts))
	for _, part := range parts {
		if broker := strings.TrimSpace(part); broker != "" {
			brokers = append(brokers, broker)
		}
	}
	return brokers
}
