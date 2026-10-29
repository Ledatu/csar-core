package readcache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func groupForTest(t *testing.T) *Group[int] {
	t.Helper()
	g, err := NewGroup[int](Limits{MaxKeys: 1, MaxFollowers: 1, MaxKeyBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func scopeForTest(t *testing.T) *Scope {
	t.Helper()
	s, err := NewScope(context.Background(), ScopeLimits{Flights: Limits{MaxKeys: 4, MaxFollowers: 128, MaxKeyBytes: 8}, MaxEntries: 2, MaxBytes: 8, MaxValueBytes: 6, MaxAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestGroupAdmissionReleaseAndOwnership(t *testing.T) {
	g := groupForTest(t)
	leader, c, release, err := g.Begin("a")
	if err != nil || !leader {
		t.Fatal("leader", err)
	}
	defer release()
	if _, _, _, err = g.Begin("b"); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	leader, follower, leave, err := g.Begin("a")
	if err != nil || leader || follower != c {
		t.Fatal("follower", err)
	}
	if _, _, _, err = g.Begin("a"); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = follower.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	leave()
	leave() // idempotent release restores follower capacity
	leader, follower, leave, err = g.Begin("a")
	if err != nil || leader || follower != c {
		t.Fatal("second leader after cancellation", err)
	}
	defer leave()
	if g.Finish("a", &Call[int]{}, 1, nil) {
		t.Fatal("foreign ticket accepted")
	}
	if !g.Finish("a", c, 42, nil) || g.Finish("a", c, 43, nil) {
		t.Fatal("finish ownership")
	}
	if v, err := follower.Wait(context.Background()); v != 42 || err != nil {
		t.Fatal(v, err)
	}
	_, next, done, err := g.Begin("a")
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if g.Finish("a", c, 99, nil) {
		t.Fatal("old ticket completed new flight")
	}
	g.Finish("a", next, 2, nil)
}

func TestPanicReleasesFollowersAndAllowsRetry(t *testing.T) {
	g := groupForTest(t)
	started, proceed := make(chan struct{}), make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		defer func() {
			if recover() == nil {
				t.Error("panic not propagated")
			}
		}()
		_, _ = g.Do(context.Background(), "a", func(context.Context) (int, error) { close(started); <-proceed; panic("test") })
	}()
	<-started
	_, c, release, err := g.Begin("a")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	close(proceed)
	<-exited
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = c.Wait(ctx); !errors.Is(err, ErrAborted) {
		t.Fatal(err)
	}
	if v, err := g.Do(ctx, "a", func(context.Context) (int, error) { return 7, nil }); v != 7 || err != nil {
		t.Fatal(v, err)
	}
}

func TestScopeConcurrentReuseOwnsBytes(t *testing.T) {
	s := scopeForTest(t)
	var calls atomic.Int64
	source := []byte("data")
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.Resolve(context.Background(), "a", func(context.Context) ([]byte, error) { calls.Add(1); return source, nil })
			if err != nil || string(v) != "data" {
				t.Error(string(v), err)
				return
			}
			v[0] = 'x'
		}()
	}
	wg.Wait()
	source[0] = 'z'
	got, err := s.Resolve(context.Background(), "a", func(context.Context) ([]byte, error) { t.Error("unexpected load"); return nil, nil })
	if err != nil || string(got) != "data" || calls.Load() != 1 {
		t.Fatal(string(got), calls.Load(), err)
	}
}

func TestScopeBoundsFailuresAndClose(t *testing.T) {
	s := scopeForTest(t)
	ctx := context.Background()
	failure := errors.New("source unavailable")
	if _, err := s.Resolve(ctx, "a", func(context.Context) ([]byte, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, "a", func(context.Context) ([]byte, error) { return []byte("1234567"), nil }); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, "a", func(context.Context) ([]byte, error) { return []byte("123456"), nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, "b", func(context.Context) ([]byte, error) { return []byte("123"), nil }); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, "b", func(context.Context) ([]byte, error) { return []byte("12"), nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, "c", func(context.Context) ([]byte, error) { t.Fatal("load beyond entry limit"); return nil, nil }); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	s.Close()
	if _, err := s.Resolve(ctx, "a", func(context.Context) ([]byte, error) { t.Fatal("load after close"); return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestScopeLifetimeCancelsLoad(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	s, err := NewScope(parent, ScopeLimits{Flights: Limits{1, 1, 8}, MaxEntries: 1, MaxBytes: 8, MaxValueBytes: 8, MaxAge: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := s.Resolve(context.Background(), "a", func(ctx context.Context) ([]byte, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() })
		result <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("load did not cancel")
	}
}

func TestInvalidConfigurationAndKey(t *testing.T) {
	if _, err := NewGroup[int](Limits{}); err == nil {
		t.Fatal("unbounded group")
	}
	if _, err := NewScope(context.Background(), ScopeLimits{}); err == nil {
		t.Fatal("unbounded scope")
	}
	for _, key := range []string{"", "123456789"} {
		if _, _, _, err := groupForTest(t).Begin(key); !errors.Is(err, ErrKey) {
			t.Fatal(err)
		}
	}
}
