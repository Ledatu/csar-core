package configload

import (
	"context"
	"log/slog"

	"github.com/ledatu/csar-core/configsource"
)

// NewValidatingWatcher creates a ConfigWatcher that validates config on each
// refresh but does not hot-apply runtime state. This is suitable for services
// that require a restart to apply config changes but want early detection of
// configuration errors.
func NewValidatingWatcher(
	source configsource.ConfigSource,
	logger *slog.Logger,
	validate func([]byte) error,
	opts ...configsource.WatcherOption,
) *configsource.ConfigWatcher {
	applyFn := func(_ context.Context, data []byte) (bool, error) {
		if err := validate(data); err != nil {
			return false, err
		}
		logger.Info("config refresh: new config validated (restart required to apply)")
		return false, nil
	}
	return configsource.NewConfigWatcher(source, applyFn, logger, opts...)
}
