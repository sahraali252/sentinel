package anomaly

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sahraali252/sentinel/detector/internal/model"
)

type State struct {
	Mean, Variance float64
	Samples        int
	Last           time.Time
}
type Store interface {
	Load(context.Context, string) (State, error)
	Save(context.Context, string, State, time.Duration) error
}
type Detector struct {
	store            Store
	alpha, threshold float64
	minimum          int
	ttl              time.Duration
	severity         string
}

func New(store Store, alpha, threshold float64, minimum int, ttl time.Duration, severity string) *Detector {
	return &Detector{store: store, alpha: alpha, threshold: threshold, minimum: minimum, ttl: ttl, severity: severity}
}

func Observe(state State, value, alpha float64) (State, float64) {
	if state.Samples == 0 {
		return State{Mean: value, Samples: 1, Last: state.Last}, 0
	}
	delta := value - state.Mean
	variance := (1 - alpha) * (state.Variance + alpha*delta*delta)
	z := 0.0
	if state.Variance > 1e-9 {
		z = delta / math.Sqrt(state.Variance)
	}
	return State{Mean: state.Mean + alpha*delta, Variance: variance, Samples: state.Samples + 1, Last: state.Last}, z
}

func (d *Detector) Check(ctx context.Context, e model.APIRequest) (*model.Finding, error) {
	key := e.SourceIP + ":" + e.Method + ":" + e.Endpoint
	state, err := d.store.Load(ctx, key)
	if err != nil {
		return nil, err
	}
	if state.Last.IsZero() {
		state.Last = e.Timestamp
		state.Samples = 0
		state, _ = Observe(state, 0, d.alpha)
		if err := d.store.Save(ctx, key, state, d.ttl); err != nil {
			return nil, err
		}
		return nil, nil
	}
	elapsed := e.Timestamp.Sub(state.Last).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	rate := 1 / elapsed
	previousSamples := state.Samples
	next, z := Observe(state, rate, d.alpha)
	next.Last = e.Timestamp
	if err := d.store.Save(ctx, key, next, d.ttl); err != nil {
		return nil, err
	}
	if previousSamples < d.minimum || z <= d.threshold {
		return nil, nil
	}
	return &model.Finding{Rule: "ewma_rate_anomaly", Severity: d.severity, Message: fmt.Sprintf("request rate %.2f/s deviates %.2fσ above baseline", rate, z), Metadata: map[string]any{"rate": rate, "z_score": z, "baseline": state.Mean, "samples": previousSamples}}, nil
}

type RedisStore struct {
	client redis.UniversalClient
	prefix string
}

func NewRedisStore(client redis.UniversalClient, prefix string) *RedisStore {
	return &RedisStore{client: client, prefix: prefix}
}
func (s *RedisStore) Load(ctx context.Context, key string) (State, error) {
	values, err := s.client.HMGet(ctx, s.prefix+":"+key, "mean", "variance", "samples", "last_ms").Result()
	if err != nil {
		return State{}, fmt.Errorf("load EWMA: %w", err)
	}
	var state State
	if values[0] == nil {
		return state, nil
	}
	_, err = fmt.Sscan(fmt.Sprint(values[0]), &state.Mean)
	if err != nil {
		return State{}, err
	}
	_, err = fmt.Sscan(fmt.Sprint(values[1]), &state.Variance)
	if err != nil {
		return State{}, err
	}
	_, err = fmt.Sscan(fmt.Sprint(values[2]), &state.Samples)
	if err != nil {
		return State{}, err
	}
	var lastMS int64
	_, err = fmt.Sscan(fmt.Sprint(values[3]), &lastMS)
	if err != nil {
		return State{}, err
	}
	state.Last = time.UnixMilli(lastMS)
	return state, nil
}
func (s *RedisStore) Save(ctx context.Context, key string, state State, ttl time.Duration) error {
	redisKey := s.prefix + ":" + key
	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, redisKey, "mean", state.Mean, "variance", state.Variance, "samples", state.Samples, "last_ms", state.Last.UnixMilli())
	pipe.Expire(ctx, redisKey, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("save EWMA: %w", err)
	}
	return nil
}
