package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sahraali252/sentinel/detector/internal/model"
)

type Postgres struct{ pool *pgxpool.Pool }

func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create Postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping Postgres: %w", err)
	}
	return &Postgres{pool: pool}, nil
}
func (p *Postgres) Close() { p.pool.Close() }
func (p *Postgres) EnsureSchema(ctx context.Context) error {
	statements := []string{`CREATE TABLE IF NOT EXISTS alerts (
id TEXT PRIMARY KEY, severity TEXT NOT NULL, rule TEXT NOT NULL, source_ip INET NOT NULL,
detected_at TIMESTAMPTZ NOT NULL, event_id TEXT NOT NULL, message TEXT NOT NULL,
metadata JSONB NOT NULL DEFAULT '{}', raw_event JSONB NOT NULL, kafka_topic TEXT NOT NULL,
kafka_partition INTEGER NOT NULL, kafka_offset BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`CREATE INDEX IF NOT EXISTS alerts_detected_at_idx ON alerts (detected_at DESC)`,
		`CREATE INDEX IF NOT EXISTS alerts_source_rule_idx ON alerts (source_ip, rule, detected_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := p.pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("ensure alert schema: %w", err)
		}
	}
	return nil
}
func (p *Postgres) SaveAlert(ctx context.Context, alert model.Alert) error {
	metadata, err := json.Marshal(alert.Metadata)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO alerts (id,severity,rule,source_ip,detected_at,event_id,message,metadata,raw_event,kafka_topic,kafka_partition,kafka_offset) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (id) DO NOTHING`, alert.ID, alert.Severity, alert.Rule, alert.SourceIP, alert.Timestamp, alert.EventID, alert.Message, metadata, alert.RawEvent, alert.KafkaTopic, alert.Partition, alert.KafkaOffset)
	if err != nil {
		return fmt.Errorf("save alert: %w", err)
	}
	return nil
}

func (p *Postgres) ListAlerts(ctx context.Context, limit int) ([]model.Alert, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT id,severity,rule,host(source_ip),detected_at,event_id,message,metadata,raw_event,kafka_topic,kafka_partition,kafka_offset FROM alerts ORDER BY detected_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()
	alerts := make([]model.Alert, 0, limit)
	for rows.Next() {
		var alert model.Alert
		if err := rows.Scan(&alert.ID, &alert.Severity, &alert.Rule, &alert.SourceIP, &alert.Timestamp, &alert.EventID, &alert.Message, &alert.Metadata, &alert.RawEvent, &alert.KafkaTopic, &alert.Partition, &alert.KafkaOffset); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

func (p *Postgres) AlertSummary(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := p.pool.Query(ctx, `SELECT severity, count(*) FROM alerts WHERE detected_at >= $1 GROUP BY severity`, since)
	if err != nil {
		return nil, fmt.Errorf("summarize alerts: %w", err)
	}
	defer rows.Close()
	result := map[string]int64{"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		result[severity] = count
		result["total"] += count
	}
	return result, rows.Err()
}
