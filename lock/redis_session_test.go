package lock

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisLocker(t *testing.T) (*RedisLocker, *redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = rdb.Close()
		mr.Close()
	})
	return NewRedisLocker(rdb), rdb, mr
}

func testRequest(key string) Request {
	return Request{
		Key:               key,
		Module:            "test-module",
		Owner:             "test-owner",
		LeaseTTL:          120 * time.Millisecond,
		HeartbeatInterval: 30 * time.Millisecond,
	}
}

func TestRedisSessionLockerAcquireConflictAndRelease(t *testing.T) {
	locker, _, _ := newTestRedisLocker(t)
	ctx := context.Background()

	session, err := locker.AcquireSession(ctx, testRequest("lock:test:conflict"))
	if err != nil {
		t.Fatalf("AcquireSession() error = %v", err)
	}

	_, err = locker.AcquireSession(ctx, testRequest("lock:test:conflict"))
	if !errors.Is(err, ErrLockNotAcquired) {
		t.Fatalf("second AcquireSession() error = %v, want ErrLockNotAcquired", err)
	}

	if err := session.Release(ctx); err != nil {
		t.Fatalf("Release() error = %v", err)
	}

	next, err := locker.AcquireSession(ctx, testRequest("lock:test:conflict"))
	if err != nil {
		t.Fatalf("AcquireSession() after release error = %v", err)
	}
	_ = next.Release(ctx)
}

func TestRedisSessionLockerHeartbeatExtendsLease(t *testing.T) {
	locker, _, _ := newTestRedisLocker(t)
	session, err := locker.AcquireSession(context.Background(), testRequest("lock:test:heartbeat"))
	if err != nil {
		t.Fatalf("AcquireSession() error = %v", err)
	}
	defer func() { _ = session.Release(context.Background()) }()

	initial := session.LeaseUntil()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if session.LeaseUntil().After(initial) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("lease was not extended: initial=%s current=%s", initial, session.LeaseUntil())
}

func TestRedisSessionLockerOwnershipLossClosesDone(t *testing.T) {
	locker, rdb, _ := newTestRedisLocker(t)
	session, err := locker.AcquireSession(context.Background(), testRequest("lock:test:lost"))
	if err != nil {
		t.Fatalf("AcquireSession() error = %v", err)
	}

	if err := rdb.Del(context.Background(), session.Key()).Err(); err != nil {
		t.Fatalf("delete lock key: %v", err)
	}

	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("session Done() did not close after ownership loss")
	}
	if !session.IsLost() {
		t.Fatal("session should be marked lost")
	}
}

func TestRedisSessionLockerProgressMetadata(t *testing.T) {
	locker, rdb, _ := newTestRedisLocker(t)
	session, err := locker.AcquireSession(context.Background(), testRequest("lock:test:progress"))
	if err != nil {
		t.Fatalf("AcquireSession() error = %v", err)
	}
	defer func() { _ = session.Release(context.Background()) }()

	if err := session.UpdateProgress(context.Background(), ProgressUpdate{
		Step:        "fetch",
		TotalSteps:  3,
		CurrentStep: 1,
		ItemsTotal:  10,
		ItemsDone:   4,
		Detail:      "page 1",
	}); err != nil {
		t.Fatalf("UpdateProgress() error = %v", err)
	}

	data, err := rdb.Get(context.Background(), "lock:session:"+session.ID()).Bytes()
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var snapshot sessionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if snapshot.Progress.Step != "fetch" || snapshot.Progress.ItemsDone != 4 {
		t.Fatalf("metadata progress = %+v, want fetch/items_done=4", snapshot.Progress)
	}
}

func TestRedisSessionLockerConcurrentProgressAndHeartbeat(t *testing.T) {
	locker, _, _ := newTestRedisLocker(t)
	session, err := locker.AcquireSession(context.Background(), testRequest("lock:test:concurrent"))
	if err != nil {
		t.Fatalf("AcquireSession() error = %v", err)
	}
	defer func() { _ = session.Release(context.Background()) }()

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = session.UpdateProgress(context.Background(), ProgressUpdate{
				Step:      "work",
				ItemsDone: int64(i + 1),
			})
		}(i)
	}
	wg.Wait()
	if session.Progress().ItemsDone == 0 {
		t.Fatal("progress was not updated")
	}
}
