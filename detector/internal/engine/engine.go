package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sahraali252/sentinel/detector/internal/detection/anomaly"
	"github.com/sahraali252/sentinel/detector/internal/detection/pattern"
	"github.com/sahraali252/sentinel/detector/internal/detection/ratelimit"
	"github.com/sahraali252/sentinel/detector/internal/model"
)

type Allowlist interface{ Allows(string, string) bool }
type AlertStore interface {
	SaveAlert(context.Context, model.Alert) error
}
type Publisher interface{ Publish(model.Alert) }
type Engine struct {
	rate                        *ratelimit.Detector
	anomaly                     *anomaly.Detector
	patterns                    *pattern.Detector
	allowlist                   Allowlist
	store                       AlertStore
	publisher                   Publisher
	rateEnabled, anomalyEnabled bool
}

func New(rate *ratelimit.Detector, anomalyDetector *anomaly.Detector, patterns *pattern.Detector, allowlist Allowlist, store AlertStore, publisher Publisher, rateEnabled, anomalyEnabled bool) *Engine {
	return &Engine{rate: rate, anomaly: anomalyDetector, patterns: patterns, allowlist: allowlist, store: store, publisher: publisher, rateEnabled: rateEnabled, anomalyEnabled: anomalyEnabled}
}

func (e *Engine) Process(ctx context.Context, raw []byte, topic string, partition int32, offset int64) error {
	var request model.APIRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return fmt.Errorf("decode event: %w", err)
	}
	if request.ID == "" || request.SourceIP == "" || request.Timestamp.IsZero() {
		return fmt.Errorf("invalid event contract")
	}
	if e.allowlist.Allows(request.SourceIP, request.Endpoint) {
		return nil
	}
	findings := make([]model.Finding, 0, 5)
	if e.rateEnabled {
		finding, err := e.rate.Check(ctx, request)
		if err != nil {
			return err
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	if e.anomalyEnabled {
		finding, err := e.anomaly.Check(ctx, request)
		if err != nil {
			return err
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	patternFindings, err := e.patterns.Check(ctx, request)
	if err != nil {
		return err
	}
	findings = append(findings, patternFindings...)
	for _, finding := range findings {
		alert := model.Alert{ID: alertID(request.ID, finding.Rule), Severity: finding.Severity, Rule: finding.Rule, SourceIP: request.SourceIP, Timestamp: time.Now().UTC(), EventID: request.ID, Message: finding.Message, Metadata: finding.Metadata, RawEvent: append([]byte(nil), raw...), KafkaTopic: topic, Partition: partition, KafkaOffset: offset}
		if err := e.store.SaveAlert(ctx, alert); err != nil {
			return err
		}
		e.publisher.Publish(alert)
	}
	return nil
}
func alertID(eventID, rule string) string {
	sum := sha256.Sum256([]byte(eventID + ":" + rule))
	return hex.EncodeToString(sum[:16])
}
