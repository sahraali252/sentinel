package consumer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type Processor interface {
	Process(context.Context, []byte, string, int32, int64) error
}
type Consumer struct {
	client     *kgo.Client
	processor  Processor
	logger     *slog.Logger
	batchSize  int
	lagWarning int64
}

func New(brokers []string, topic, group string, batchSize int, lagWarning int64, processor Processor, logger *slog.Logger) (*Consumer, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumeTopics(topic),
		kgo.ConsumerGroup(group),
		kgo.Balancers(kgo.CooperativeStickyBalancer()),
		kgo.DisableAutoCommit(),
		kgo.FetchMaxWait(500*time.Millisecond),
		kgo.OnPartitionsAssigned(func(_ context.Context, _ *kgo.Client, assigned map[string][]int32) {
			logger.Info("Kafka partitions assigned", "partitions", assigned)
		}),
		kgo.OnPartitionsRevoked(func(_ context.Context, _ *kgo.Client, revoked map[string][]int32) {
			logger.Info("Kafka partitions revoked", "partitions", revoked)
		}),
		kgo.OnPartitionsLost(func(_ context.Context, _ *kgo.Client, lost map[string][]int32) {
			logger.Error("Kafka partitions lost; uncommitted records will replay", "partitions", lost)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("create Kafka consumer: %w", err)
	}
	return &Consumer{client: client, processor: processor, logger: logger, batchSize: batchSize, lagWarning: lagWarning}, nil
}

func (c *Consumer) Ping(ctx context.Context) error {
	if err := c.client.Ping(ctx); err != nil {
		return fmt.Errorf("ping Kafka: %w", err)
	}
	return nil
}
func (c *Consumer) Close() { c.client.Close() }

func (c *Consumer) Run(ctx context.Context) error {
	for {
		fetches := c.client.PollRecords(ctx, c.batchSize)
		if ctx.Err() != nil {
			return nil
		}
		if errs := fetches.Errors(); len(errs) > 0 {
			for _, fetchErr := range errs {
				c.logger.Error("Kafka fetch failed", "topic", fetchErr.Topic, "partition", fetchErr.Partition, "error", fetchErr.Err)
			}
			continue
		}
		groups := make(map[string][]*kgo.Record)
		allRecords := make([]*kgo.Record, 0, fetches.NumRecords())
		fetches.EachPartition(func(partition kgo.FetchTopicPartition) {
			if len(partition.Records) == 0 {
				return
			}
			lag := partition.HighWatermark - partition.Records[len(partition.Records)-1].Offset - 1
			if lag >= c.lagWarning {
				c.logger.Warn("detector consumer lag elevated", "topic", partition.Topic, "partition", partition.Partition, "lag", lag)
			}
			key := fmt.Sprintf("%s:%d", partition.Topic, partition.Partition)
			groups[key] = partition.Records
			allRecords = append(allRecords, partition.Records...)
		})
		if len(allRecords) == 0 {
			continue
		}
		errCh := make(chan error, len(groups))
		var wg sync.WaitGroup
		for _, records := range groups {
			records := records
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, record := range records {
					if err := c.processor.Process(ctx, record.Value, record.Topic, record.Partition, record.Offset); err != nil {
						errCh <- fmt.Errorf("process %s[%d]@%d: %w", record.Topic, record.Partition, record.Offset, err)
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errCh)
		failed := false
		for err := range errCh {
			failed = true
			c.logger.Error("batch processing failed; offsets not committed", "error", err)
		}
		if failed {
			continue
		}
		if err := c.client.CommitRecords(ctx, allRecords...); err != nil {
			c.logger.Error("Kafka commit failed; batch will replay", "error", err)
			continue
		}
		c.logger.Debug("Kafka batch committed", "records", len(allRecords))
	}
}
