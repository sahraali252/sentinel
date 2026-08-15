package ratelimit

import (
	"context"
	"github.com/sahraali252/sentinel/detector/internal/model"
	"testing"
	"time"
)

type fakeCounter struct{ count int64 }

func (f fakeCounter) Add(context.Context, string, string, time.Time, time.Duration) (int64, error) {
	return f.count, nil
}
func TestThresholdBoundary(t *testing.T) {
	e := model.APIRequest{ID: "e", SourceIP: "192.0.2.1", Timestamp: time.Now()}
	for _, tt := range []struct {
		name  string
		count int64
		alert bool
	}{{"below", 9, false}, {"exact", 10, false}, {"above", 11, true}} {
		t.Run(tt.name, func(t *testing.T) {
			finding, err := New(fakeCounter{tt.count}, 10, time.Second, "medium").Check(context.Background(), e)
			if err != nil {
				t.Fatal(err)
			}
			if (finding != nil) != tt.alert {
				t.Fatalf("finding=%v want alert=%v", finding, tt.alert)
			}
		})
	}
}
