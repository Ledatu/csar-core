package lock

import (
	"context"
	"errors"
	"sync"
	"time"
)

// SessionLocker acquires renewable lock sessions.
type SessionLocker interface {
	AcquireSession(ctx context.Context, req Request) (*Session, error)
}

// Request describes a renewable lock session acquisition.
type Request struct {
	Key               string
	Module            string
	Owner             string
	LeaseTTL          time.Duration
	HeartbeatInterval time.Duration
	MaxDuration       time.Duration
	Metadata          map[string]string
	InitialProgress   Progress
}

// Progress is structured, optional session progress metadata.
type Progress struct {
	Step        string    `json:"step,omitempty"`
	TotalSteps  int       `json:"total_steps,omitempty"`
	CurrentStep int       `json:"current_step,omitempty"`
	ItemsTotal  int64     `json:"items_total,omitempty"`
	ItemsDone   int64     `json:"items_done,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// ProgressUpdate updates non-zero progress fields on a session.
type ProgressUpdate struct {
	Step        string
	TotalSteps  int
	CurrentStep int
	ItemsTotal  int64
	ItemsDone   int64
	Detail      string
	LastError   string
}

// Session represents a held renewable lock.
type Session struct {
	mu sync.RWMutex

	id         string
	key        string
	module     string
	owner      string
	startedAt  time.Time
	leaseUntil time.Time
	progress   Progress
	metadata   map[string]string

	lostErr error
	done    chan struct{}
	stop    chan struct{}

	onUpdate  func(context.Context, *Session) error
	onRelease func() error
	once      sync.Once
}

func newSession(req *Request, id string, startedAt, leaseUntil time.Time) *Session {
	progress := req.InitialProgress
	if progress.UpdatedAt.IsZero() {
		progress.UpdatedAt = startedAt
	}
	metadata := make(map[string]string, len(req.Metadata))
	for k, v := range req.Metadata {
		metadata[k] = v
	}
	return &Session{
		id:         id,
		key:        req.Key,
		module:     req.Module,
		owner:      req.Owner,
		startedAt:  startedAt,
		leaseUntil: leaseUntil,
		progress:   progress,
		metadata:   metadata,
		done:       make(chan struct{}),
		stop:       make(chan struct{}),
	}
}

// ID returns the unique session ID.
func (s *Session) ID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.id
}

// Key returns the lock key.
func (s *Session) Key() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key
}

// Module returns the module that acquired the session.
func (s *Session) Module() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.module
}

// Owner returns the process owner string for this session.
func (s *Session) Owner() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.owner
}

// StartedAt returns when the session was acquired.
func (s *Session) StartedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.startedAt
}

// LeaseUntil returns the last confirmed lease deadline.
func (s *Session) LeaseUntil() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.leaseUntil
}

// Progress returns a copy of the current session progress.
func (s *Session) Progress() Progress {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.progress
}

// Err returns ErrSessionLost when the session has lost ownership.
func (s *Session) Err() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lostErr
}

// IsLost reports whether the session has lost ownership.
func (s *Session) IsLost() bool {
	return errors.Is(s.Err(), ErrSessionLost)
}

// Done is closed when the session is released or lost.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// UpdateProgress records structured progress for monitoring and debugging.
//
//nolint:gocritic // Preserve the existing session API when moving it into csar-core.
func (s *Session) UpdateProgress(ctx context.Context, update ProgressUpdate) error {
	s.mu.Lock()
	s.applyProgressLocked(&update, time.Now().UTC())
	s.mu.Unlock()
	if s.onUpdate != nil {
		return s.onUpdate(ctx, s)
	}
	return nil
}

// Release releases the session. Redis-backed sessions use an internal cleanup
// context, so callers may pass an already-cancelled handler context safely.
func (s *Session) Release(context.Context) error {
	var err error
	s.once.Do(func() {
		close(s.stop)
		if s.onRelease != nil {
			err = s.onRelease()
		}
		close(s.done)
	})
	return err
}

func (s *Session) setLeaseUntil(until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaseUntil = until
}

func (s *Session) markLost(err error) {
	s.mu.Lock()
	if s.lostErr == nil {
		if err == nil {
			err = ErrSessionLost
		}
		s.lostErr = err
		s.mu.Unlock()
		s.once.Do(func() {
			close(s.stop)
			close(s.done)
		})
		return
	}
	s.mu.Unlock()
}

func (s *Session) applyProgressLocked(update *ProgressUpdate, now time.Time) {
	if update.Step != "" {
		s.progress.Step = update.Step
	}
	if update.TotalSteps != 0 {
		s.progress.TotalSteps = update.TotalSteps
	}
	if update.CurrentStep != 0 {
		s.progress.CurrentStep = update.CurrentStep
	}
	if update.ItemsTotal != 0 {
		s.progress.ItemsTotal = update.ItemsTotal
	}
	if update.ItemsDone != 0 {
		s.progress.ItemsDone = update.ItemsDone
	}
	if update.Detail != "" {
		s.progress.Detail = update.Detail
	}
	if update.LastError != "" {
		s.progress.LastError = update.LastError
	}
	s.progress.UpdatedAt = now
}

type sessionSnapshot struct {
	ID         string            `json:"id"`
	Key        string            `json:"key"`
	Module     string            `json:"module"`
	Owner      string            `json:"owner"`
	StartedAt  time.Time         `json:"started_at"`
	LeaseUntil time.Time         `json:"lease_until"`
	Progress   Progress          `json:"progress"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func (s *Session) snapshot() sessionSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	metadata := make(map[string]string, len(s.metadata))
	for k, v := range s.metadata {
		metadata[k] = v
	}
	return sessionSnapshot{
		ID:         s.id,
		Key:        s.key,
		Module:     s.module,
		Owner:      s.owner,
		StartedAt:  s.startedAt,
		LeaseUntil: s.leaseUntil,
		Progress:   s.progress,
		Metadata:   metadata,
	}
}

type sessionContextKey struct{}

// ContextWithSession stores a lock session in ctx.
func ContextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, session)
}

// SessionFromContext returns a lock session from ctx when one is present.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(sessionContextKey{}).(*Session)
	return session, ok
}
