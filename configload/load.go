// Package configload provides generic helpers for loading and watching
// configuration via csar-core/configsource. It eliminates the repeated
// LoadInitial + BuildSource + parse boilerplate in each service.
package configload

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ledatu/csar-core/configsource"
)

// LoadInitial builds a config source from params, fetches the config once,
// and parses it using the caller-supplied parse function.
func LoadInitial[T any](
	ctx context.Context,
	params *configsource.SourceParams,
	logger *slog.Logger,
	parse func([]byte) (*T, error),
) (*T, error) {
	src, err := configsource.BuildSource(params, logger)
	if err != nil {
		return nil, err
	}

	fetched, err := src.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching config: %w", err)
	}
	if fetched.Data == nil {
		return nil, fmt.Errorf("config source returned empty data")
	}

	return parse(fetched.Data)
}
