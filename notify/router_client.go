package notify

import (
	"fmt"
	"log/slog"

	"github.com/ledatu/csar-core/stsclient"
)

// NewRouterClient creates an async notify client that POSTs to the central
// notify ingest endpoint through the csar router using STS bearer tokens.
// A nil or unconfigured cfg disables notification emission and returns nil, nil.
func NewRouterClient(cfg *stsclient.ServiceAuthConfig, logger *slog.Logger) (*Client, error) {
	if cfg == nil || !cfg.IsConfigured() {
		return nil, nil
	}

	rc, err := stsclient.NewRouterClient(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("notify router client: %w", err)
	}

	return NewClient(ClientConfig{
		Transport: NewHTTPTransport(rc.Client, rc.BaseURL),
	}, logger)
}
