package lock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-redsync/redsync/v4"
	goredislib "github.com/go-redsync/redsync/v4/redis/goredis/v9"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// RedisLocker implements Locker using redsync (Redlock algorithm).
type RedisLocker struct {
	client *redis.Client
	rs     *redsync.Redsync
}

// NewRedisLocker creates a locker backed by the given Redis client.
func NewRedisLocker(client *redis.Client) *RedisLocker {
	pool := goredislib.NewPool(client)
	return &RedisLocker{client: client, rs: redsync.New(pool)}
}

// Acquire obtains a distributed lock via Redlock.
func (rl *RedisLocker) Acquire(ctx context.Context, key string, ttl time.Duration) (func() error, error) {
	mutex := rl.rs.NewMutex(key,
		redsync.WithExpiry(ttl),
		redsync.WithTries(1),
	)

	if err := mutex.LockContext(ctx); err != nil {
		return nil, ErrLockNotAcquired
	}

	unlock := func() error {
		if ok, err := mutex.UnlockContext(ctx); !ok || err != nil {
			return err
		}
		return nil
	}
	return unlock, nil
}

// AcquireSession obtains a renewable Redis-backed lock session.
//
//nolint:gocritic // Preserve the public value-parameter API used by existing callers.
func (rl *RedisLocker) AcquireSession(ctx context.Context, req Request) (*Session, error) {
	if req.LeaseTTL <= 0 {
		return nil, fmt.Errorf("lock: lease ttl must be positive")
	}
	if req.HeartbeatInterval <= 0 {
		return nil, fmt.Errorf("lock: heartbeat interval must be positive")
	}

	mutex := rl.rs.NewMutex(req.Key,
		redsync.WithExpiry(req.LeaseTTL),
		redsync.WithTries(1),
	)
	if err := mutex.LockContext(ctx); err != nil {
		return nil, ErrLockNotAcquired
	}

	now := time.Now().UTC()
	session := newSession(&req, uuid.NewString(), now, mutex.Until())
	state := &redisSessionState{
		locker:            rl,
		mutex:             mutex,
		metadataKey:       "lock:session:" + session.ID(),
		metadataTTL:       req.LeaseTTL + req.HeartbeatInterval,
		leaseTTL:          req.LeaseTTL,
		heartbeatInterval: req.HeartbeatInterval,
		maxDuration:       req.MaxDuration,
	}
	state.lastConfirmedLeaseUntil = mutex.Until()
	session.onUpdate = state.persist
	session.onRelease = state.release
	_ = state.persist(context.Background(), session)
	go state.heartbeat(session)
	return session, nil
}

type redisSessionState struct {
	locker            *RedisLocker
	mutex             *redsync.Mutex
	metadataKey       string
	metadataTTL       time.Duration
	leaseTTL          time.Duration
	heartbeatInterval time.Duration
	maxDuration       time.Duration

	mu                      sync.Mutex
	lastConfirmedLeaseUntil time.Time
}

func (rs *redisSessionState) heartbeat(session *Session) {
	ticker := time.NewTicker(rs.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-session.stop:
			return
		case <-ticker.C:
			if rs.maxDuration > 0 && time.Since(session.StartedAt()) >= rs.maxDuration {
				session.markLost(ErrSessionLost)
				return
			}
			if err := rs.extendOnce(session); err != nil {
				session.markLost(err)
				return
			}
		}
	}
}

func (rs *redisSessionState) extendOnce(session *Session) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), rs.heartbeatInterval)
	defer cancel()
	ok, err := rs.mutex.ExtendContext(ctx)
	now := time.Now().UTC()
	if ok && err == nil {
		until := rs.mutex.Until()
		rs.lastConfirmedLeaseUntil = until
		session.setLeaseUntil(until)
		_ = rs.persist(context.Background(), session)
		return nil
	}
	if isOwnershipLoss(err) || (err == nil && !ok) {
		return ErrSessionLost
	}
	if now.Before(rs.lastConfirmedLeaseUntil) {
		return nil
	}
	return ErrSessionLost
}

func (rs *redisSessionState) persist(ctx context.Context, session *Session) error {
	data, err := json.Marshal(session.snapshot())
	if err != nil {
		return fmt.Errorf("marshal lock session: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return rs.locker.client.Set(ctx, rs.metadataKey, data, rs.metadataTTL).Err()
}

func (rs *redisSessionState) release() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := rs.mutex.UnlockContext(ctx)
	if err != nil && !errors.Is(err, redsync.ErrLockAlreadyExpired) {
		return err
	}
	if ok {
		_ = rs.locker.client.Del(ctx, rs.metadataKey).Err()
	}
	return nil
}

func isOwnershipLoss(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, redsync.ErrLockAlreadyExpired) {
		return true
	}
	var taken *redsync.ErrTaken
	return errors.As(err, &taken)
}
