package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/sahraali252/sentinel/detector/internal/detection/window"
	"github.com/sahraali252/sentinel/detector/internal/model"
)

type Detector struct {
	counter  window.Counter
	limit    int
	width    time.Duration
	severity string
}

func New(counter window.Counter, limit int, width time.Duration, severity string) *Detector {
	return &Detector{counter: counter, limit: limit, width: width, severity: severity}
}
func (d *Detector) Check(ctx context.Context, e model.APIRequest) (*model.Finding, error) {
	count, err := d.counter.Add(ctx, e.SourceIP, e.ID, e.Timestamp, d.width)
	if err != nil {
		return nil, err
	}
	if count <= int64(d.limit) {
		return nil, nil
	}
	return &model.Finding{Rule: "sliding_window_rate", Severity: d.severity, Message: fmt.Sprintf("%d requests observed in %s (limit %d)", count, d.width, d.limit), Metadata: map[string]any{"count": count, "limit": d.limit, "window_ms": d.width.Milliseconds()}}, nil
}
