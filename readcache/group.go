// Package readcache supplies bounded, process-local reuse primitives. It does
// not choose authorization, semantic keys, freshness or distributed ownership.
package readcache

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrCapacity = errors.New("readcache capacity exhausted")
	ErrKey      = errors.New("readcache key is empty or too long")
	ErrAborted  = errors.New("readcache leader aborted")
)

// Limits bound live keys and concurrently attached followers, not request rate.
type Limits struct {
	MaxKeys      int
	MaxFollowers int
	MaxKeyBytes  int
}

// Group joins callers only while a load is in flight. It does not retain results.
// Values must be immutable after Finish; callers clone mutable values as needed.
type Group[T any] struct {
	mu     sync.Mutex
	limits Limits
	calls  map[string]*Call[T]
}

type Call[T any] struct {
	done      chan struct{}
	value     T
	err       error
	followers int // guarded by Group.mu
}

func NewGroup[T any](limits Limits) (*Group[T], error) {
	if limits.MaxKeys <= 0 || limits.MaxFollowers <= 0 || limits.MaxKeyBytes <= 0 {
		return nil, errors.New("readcache limits must be positive")
	}
	return &Group[T]{limits: limits, calls: make(map[string]*Call[T])}, nil
}

// Begin returns a leader ticket or attaches a follower. Every admitted caller
// must defer release; leaders must also Finish, including when their load panics.
// Releasing a follower never cancels the leader or allows a second leader.
func (g *Group[T]) Begin(key string) (leader bool, call *Call[T], release func(), err error) {
	if len(key) == 0 || len(key) > g.limits.MaxKeyBytes {
		return false, nil, nil, ErrKey
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if call = g.calls[key]; call != nil {
		if call.followers >= g.limits.MaxFollowers {
			return false, nil, nil, ErrCapacity
		}
		call.followers++
		var once sync.Once
		return false, call, func() { once.Do(func() { g.mu.Lock(); call.followers--; g.mu.Unlock() }) }, nil
	}
	if len(g.calls) >= g.limits.MaxKeys {
		return false, nil, nil, ErrCapacity
	}
	call = &Call[T]{done: make(chan struct{})}
	g.calls[key] = call
	return true, call, func() {}, nil
}

// Finish is idempotent and accepts only the current ticket for this key.
func (g *Group[T]) Finish(key string, call *Call[T], value T, err error) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if call == nil || g.calls[key] != call {
		return false
	}
	call.value, call.err = value, err
	delete(g.calls, key)
	close(call.done)
	return true
}

func (c *Call[T]) Done() <-chan struct{} { return c.done }

// Wait does not transfer caller cancellation to the leader. A leader's own
// error (including cancellation) is shared; followers never retry automatically.
func (c *Call[T]) Wait(ctx context.Context) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-c.done:
		return c.value, c.err
	}
}

func (g *Group[T]) Do(ctx context.Context, key string, load func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	leader, call, release, err := g.Begin(key)
	if err != nil {
		return zero, err
	}
	defer release()
	if !leader {
		return call.Wait(ctx)
	}
	// Unblock followers even when the caller's panic is recovered above us.
	defer g.Finish(key, call, zero, ErrAborted)
	value, err := load(ctx)
	g.Finish(key, call, value, err)
	return value, err
}
