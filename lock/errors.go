package lock

import "errors"

// ErrLockNotAcquired is returned when a lock is already held by another process.
var ErrLockNotAcquired = errors.New("lock: not acquired")

// ErrSessionLost is returned when a lock session can no longer prove ownership.
var ErrSessionLost = errors.New("lock: session lost")
