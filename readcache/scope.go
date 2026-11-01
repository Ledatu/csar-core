package readcache

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"
)

// ScopeLimits bound one job/request, including entries reserved by active loads.
// MaxBytes limits retained payloads; providers must bound their own working set.
type ScopeLimits struct {
	Flights       Limits
	MaxEntries    int
	MaxBytes      int
	MaxValueBytes int
	MaxAge        time.Duration
}

// Scope memoizes successful byte values during one bounded operation. It owns
// copies on ingress and egress. Never use it as a process-global report cache.
type Scope struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	limits  ScopeLimits
	entries map[string][]byte
	bytes   int
	group   *Group[[]byte]
}

func NewScope(parent context.Context, limits ScopeLimits) (*Scope, error) {
	if limits.MaxEntries <= 0 || limits.MaxBytes <= 0 || limits.MaxValueBytes <= 0 || limits.MaxValueBytes > limits.MaxBytes || limits.MaxAge <= 0 {
		return nil, errors.New("readcache scope requires positive bounded storage and lifetime")
	}
	group, err := NewGroup[[]byte](limits.Flights)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, limits.MaxAge)
	return &Scope{ctx: ctx, cancel: cancel, limits: limits, entries: make(map[string][]byte), group: group}, nil
}

func (s *Scope) Close() {
	s.cancel()
	s.mu.Lock()
	clear(s.entries)
	s.bytes = 0
	s.mu.Unlock()
}

func (s *Scope) Resolve(ctx context.Context, key string, load func(context.Context) ([]byte, error)) ([]byte, error) {
	// Scope expiry cancels both leaders and followers, even if their context lives
	// longer. Loaders must honor cancellation, as with any context-aware Go API.
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	value, err := s.group.Do(ctx, key, func(ctx context.Context) ([]byte, error) {
		s.mu.Lock()
		if existing := s.entries[key]; existing != nil {
			s.mu.Unlock()
			return existing, nil
		}
		if len(s.entries) >= s.limits.MaxEntries {
			s.mu.Unlock()
			return nil, ErrCapacity
		}
		s.entries[key] = nil // reserve before calling a potentially expensive provider
		s.mu.Unlock()
		committed := false
		defer func() {
			if !committed {
				s.mu.Lock()
				delete(s.entries, key)
				s.mu.Unlock()
			}
		}()
		data, loadErr := load(ctx)
		if loadErr != nil {
			return nil, loadErr
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(data) > s.limits.MaxValueBytes {
			return nil, ErrCapacity
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.ctx.Err(); err != nil {
			return nil, err
		}
		if len(data) > s.limits.MaxBytes-s.bytes {
			return nil, ErrCapacity
		}
		owned := make([]byte, len(data)) // non-nil, including an empty success
		copy(owned, data)
		s.entries[key] = owned
		s.bytes += len(owned)
		committed = true
		return owned, nil
	})
	if err != nil {
		return nil, err
	}
	return bytes.Clone(value), nil
}
