package audit

import (
	"fmt"
	"log/slog"

	"github.com/ledatu/csar-core/stsclient"
)

// NewRouterClient creates an async audit client that POSTs to the central
// audit ingest endpoint through the csar router using STS bearer tokens.
// A nil or unconfigured cfg disables audit emission and returns nil, nil.
func NewRouterClient(cfg *stsclient.ServiceAuthConfig, logger *slog.Logger) (*Client, error) {
	if cfg == nil || !cfg.IsConfigured() {
		return nil, nil
	}

	rc, err := stsclient.NewRouterClient(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("audit router client: %w", err)
	}

	return NewClient(ClientConfig{
		Transport: NewHTTPTransport(rc.Client, rc.BaseURL),
	}, logger)
}
