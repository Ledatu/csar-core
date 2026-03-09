package configsource

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ApplyFunc is called with new config bytes when a change is detected.
// It should parse, validate, and apply the config. Returns true if the
// config caused observable changes, false if it was a no-op.
type ApplyFunc func(ctx context.Context, data []byte) (changed bool, err error)

// ConfigWatcher periodically polls a ConfigSource, validates integrity
// via SHA-256 hashing, and delegates application to a caller-supplied
// ApplyFunc. This keeps the watcher generic and reusable across all
// services (csar, csar-authn, csar-authz, etc.).
type ConfigWatcher struct {
	source  ConfigSource
	applyFn ApplyFunc
	logger  *slog.Logger

	mu         sync.Mutex
	lastETag   string
	lastHash   string
	hashPolicy HashPolicy
	pinnedHash string
}

// WatcherOption configures a ConfigWatcher.
type WatcherOption func(*ConfigWatcher)

// WithHashPolicy sets the hash validation strategy.
func WithHashPolicy(p HashPolicy) WatcherOption {
	return func(w *ConfigWatcher) { w.hashPolicy = p }
}

// WithPinnedHash sets the expected SHA-256 hash for HashPinned policy.
func WithPinnedHash(hash string) WatcherOption {
	return func(w *ConfigWatcher) { w.pinnedHash = hash }
}

// NewConfigWatcher creates a generic config watcher. The applyFn is called
// every time new (changed) config bytes are fetched. Hash policy defaults
// to TOFU.
func NewConfigWatcher(
	source ConfigSource,
	applyFn ApplyFunc,
	logger *slog.Logger,
	opts ...WatcherOption,
) *ConfigWatcher {
	w := &ConfigWatcher{
		source:     source,
		applyFn:    applyFn,
		logger:     logger,
		hashPolicy: HashTOFU,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Apply performs one cycle: fetch -> hash validation -> change detection -> applyFn.
// Hash validation always runs when data is present, even when ETag is unchanged,
// to detect same-ETag content tampering.
func (w *ConfigWatcher) Apply(ctx context.Context) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	fetched, err := w.source.Fetch(ctx)
	if err != nil {
		return false, fmt.Errorf("fetching config: %w", err)
	}

	if fetched.Data == nil {
		return false, nil
	}

	currentHash := ComputeSHA256(fetched.Data)

	if err := ValidateHash(w.hashPolicy, w.pinnedHash, currentHash, w.lastHash, fetched.ETag, w.lastETag); err != nil {
		return false, fmt.Errorf("hash validation: %w", err)
	}

	if fetched.ETag != "" && fetched.ETag == w.lastETag && currentHash == w.lastHash {
		return false, nil
	}

	changed, err := w.applyFn(ctx, fetched.Data)
	if err != nil {
		w.lastETag = ""
		return false, fmt.Errorf("applying config: %w", err)
	}

	w.lastETag = fetched.ETag
	w.lastHash = currentHash

	if changed {
		w.logger.Info("config applied", "sha256", currentHash)
	} else {
		w.logger.Debug("config unchanged after apply", "sha256", currentHash)
	}

	return changed, nil
}

// RunPeriodicWatch starts a background loop that polls the config source
// at the given interval. It blocks until ctx is cancelled.
func (w *ConfigWatcher) RunPeriodicWatch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("config watch loop stopped")
			return
		case <-ticker.C:
			changed, err := w.Apply(ctx)
			if err != nil {
				w.logger.Error("config refresh failed", "error", err)
				continue
			}
			if changed {
				w.logger.Info("config updated from source")
			}
		}
	}
}
