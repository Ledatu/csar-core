package usagebudget

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestAtomicFleetAdmissionAcrossReplicas(t *testing.T) {
	store := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: store.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true})
	defer client.Close()
	first, err := New(client, "test:", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(client, "test:", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var allowed atomic.Int32
	var group sync.WaitGroup
	for i := range 50 {
		group.Add(1)
		go func() {
			defer group.Done()
			limiter := first
			if i%2 == 0 {
				limiter = second
			}
			err := limiter.Take(context.Background(), Request{Policy: "reports", Window: time.Minute, Units: 1, Limits: []Limit{{"caller", "stable-caller", 100}, {"owner", "stable-owner", 100}, {"fleet", "all", 10}}})
			if err == nil {
				allowed.Add(1)
			} else {
				var exceeded *Exceeded
				if !errors.As(err, &exceeded) || exceeded.Dimension != "fleet" || exceeded.RetryAfter <= 0 {
					t.Error(err)
				}
			}
		}()
	}
	group.Wait()
	if allowed.Load() != 10 {
		t.Fatal("fleet limit split by replica", allowed.Load())
	}
	key := first.key("reports", Limit{Dimension: "caller", Subject: "stable-caller"})
	if value, err := store.Get(key); err != nil || value != "10" {
		t.Fatal("denial partially charged caller", value, err)
	}
	store.FastForward(time.Minute)
	if err := first.Take(context.Background(), Request{Policy: "reports", Window: time.Minute, Units: 1, Limits: []Limit{{"fleet", "all", 10}}}); err != nil {
		t.Fatal("window did not expire", err)
	}
}

func TestStableOwnerAndUnavailableFailClosed(t *testing.T) {
	store := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: store.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true})
	defer client.Close()
	limiter, err := New(client, "test:", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Policy: "analytics.read", Window: time.Minute, Units: 1, Limits: []Limit{{"caller", "agent-one", 10}, {"owner", "owner", 1}}}
	if err := limiter.Take(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Limits[0].Subject = "agent-two" // new caller/credential cannot reset owner
	var exceeded *Exceeded
	if err := limiter.Take(context.Background(), request); !errors.As(err, &exceeded) || exceeded.Dimension != "owner" {
		t.Fatal("owner limit reset", err)
	}
	if store.Exists(limiter.key(request.Policy, request.Limits[0])) {
		t.Fatal("denial allocated new caller state")
	}
	store.Close()
	if err := limiter.Take(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatal("Redis outage bypassed usage", err)
	}
}

func TestInvalidStateCannotGrantUsage(t *testing.T) {
	store := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: store.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true})
	defer client.Close()
	limiter, err := New(client, "test:", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Policy: "reports", Window: time.Minute, Units: 1, Limits: []Limit{{"fleet", "all", 10}}}
	if err := store.Set(limiter.key("reports", request.Limits[0]), "broken"); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Take(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatal("corrupt state admitted", err)
	}
	request.Limits = append(request.Limits, request.Limits[0])
	if err := limiter.Take(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate dimension accepted")
	}
	if _, err := New(client, "unsafe{tag}", time.Second); err == nil {
		t.Fatal("external hash-tag accepted")
	}
}
