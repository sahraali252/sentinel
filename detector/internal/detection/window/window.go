package window

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Counter interface {
	Add(context.Context, string, string, time.Time, time.Duration) (int64, error)
}

type RedisCounter struct {
	client redis.UniversalClient
	prefix string
}

func NewRedisCounter(client redis.UniversalClient, prefix string) *RedisCounter {
	return &RedisCounter{client: client, prefix: prefix}
}

var slidingWindowScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
local count = redis.call('ZCARD', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return count
`)

func (c *RedisCounter) Add(ctx context.Context, key, member string, at time.Time, width time.Duration) (int64, error) {
	redisKey := c.prefix + ":" + key
	cutoff := at.Add(-width).UnixMilli()
	count, err := slidingWindowScript.Run(ctx, c.client, []string{redisKey}, cutoff, at.UnixMilli(), member, width.Milliseconds()+1000).Int64()
	if err != nil {
		return 0, fmt.Errorf("update sliding window: %w", err)
	}
	return count, nil
}
