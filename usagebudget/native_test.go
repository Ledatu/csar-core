package usagebudget

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Opt-in against a disposable localhost fixture, never production or FLUSHDB.
func TestNativeRedisAtomicAdmission(t *testing.T) {
	address := os.Getenv("USAGEBUDGET_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("set USAGEBUDGET_TEST_REDIS_ADDR for a disposable localhost Redis")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("native fixture must use 127.0.0.1")
	}
	client := redis.NewClient(&redis.Options{Addr: address, MaxRetries: -1, ContextTimeoutEnabled: true})
	defer client.Close()
	limiter, err := New(client, "test:"+uuid.NewString()+":", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Policy: "reports", Window: time.Minute, Units: 1, Limits: []Limit{{"caller", "agent", 20}, {"fleet", "all", 7}}}
	keys := []string{limiter.key(request.Policy, request.Limits[0]), limiter.key(request.Policy, request.Limits[1])}
	defer client.Del(context.Background(), keys...)
	var allowed atomic.Int32
	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			err := limiter.Take(context.Background(), request)
			if err == nil {
				allowed.Add(1)
			} else {
				var exceeded *Exceeded
				if !errors.As(err, &exceeded) {
					t.Error(err)
				}
			}
		}()
	}
	group.Wait()
	if allowed.Load() != 7 {
		t.Fatal("native Lua did not enforce fleet quota", allowed.Load())
	}
	for _, key := range keys {
		if value, err := client.Get(context.Background(), key).Result(); err != nil || value != "7" {
			t.Fatal("native denial partially charged", value, err)
		}
	}
}
