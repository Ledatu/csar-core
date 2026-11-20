package lock

import (
	"context"
	"time"
)

// Locker is the interface for distributed lock implementations.
type Locker interface {
	// Acquire attempts to acquire a lock for the given key.
	// On success it returns an unlock function that must be called to release.
	// If the lock cannot be acquired (already held), it returns ErrLockNotAcquired.
	Acquire(ctx context.Context, key string, ttl time.Duration) (unlock func() error, err error)
}
