package configsource

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/ledatu/csar-core/s3store"
	"github.com/ledatu/csar-core/ycloud"
)

// ManifestSource implements ConfigSource by first fetching a manifest
// document, resolving the entry for a specific service, and then fetching the
// actual config payload from the provider declared in that entry. It composes
// with ConfigWatcher and HashPolicy without modification.
type ManifestSource struct {
	bootstrap   ConfigSource
	serviceName string
	auth        ycloud.AuthConfig
	logger      *slog.Logger

	mu          sync.Mutex
	lastVersion string       // service version from last resolved manifest
	lastCksum   string       // checksum value from last resolved manifest
	resolvedSrc ConfigSource // cached source for current config resource
	resolvedCR  *ConfigResource
}

// NewManifestSource creates a ManifestSource.
//
// bootstrap is the ConfigSource used to fetch the manifest itself (file, S3,
// HTTP). serviceName is the key looked up inside manifest.services. auth
// supplies S3 credentials used when resolving s3-provider config entries;
// it is ignored for file/http providers.
func NewManifestSource(
	bootstrap ConfigSource,
	serviceName string,
	auth *ycloud.AuthConfig,
	logger *slog.Logger,
) *ManifestSource {
	return &ManifestSource{
		bootstrap:   bootstrap,
		serviceName: serviceName,
		auth:        *auth,
		logger:      logger,
	}
}

// Fetch retrieves the manifest, resolves the service entry, fetches the
// actual config, and validates the checksum if present.
func (ms *ManifestSource) Fetch(ctx context.Context) (FetchedConfig, error) {
	fetched, err := ms.bootstrap.Fetch(ctx)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("fetching manifest: %w", err)
	}

	if fetched.Data == nil {
		return FetchedConfig{Data: nil, ETag: fetched.ETag}, nil
	}

	manifest, err := ParseManifest(fetched.Data)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("manifest parse: %w", err)
	}

	if manifest.TraceID != "" {
		ms.logger.Info("manifest fetched",
			"trace_id", manifest.TraceID,
			"environment", manifest.Environment,
			"updated_at", manifest.UpdatedAt,
		)
	}

	svc, err := manifest.LookupService(ms.serviceName)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("manifest lookup: %w", err)
	}

	cksum := ""
	if svc.Config.Checksum != nil {
		cksum = svc.Config.Checksum.Value
	}

	syntheticETag := "manifest:" + fetched.ETag +
		":svc:" + svc.Version +
		":cksum:" + cksum

	ms.mu.Lock()
	unchanged := svc.Version == ms.lastVersion && cksum == ms.lastCksum && ms.lastVersion != ""
	ms.mu.Unlock()

	if unchanged {
		ms.logger.Debug("manifest service entry unchanged",
			"service", ms.serviceName,
			"version", svc.Version,
		)
		return FetchedConfig{Data: nil, ETag: syntheticETag}, nil
	}

	src, err := ms.resolveSource(&svc.Config)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("resolving config source for %s: %w", ms.serviceName, err)
	}

	configFetched, err := src.Fetch(ctx)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("fetching config for %s via %s: %w",
			ms.serviceName, svc.Config.Provider, err)
	}

	if configFetched.Data == nil {
		return FetchedConfig{Data: nil, ETag: syntheticETag}, nil
	}

	if svc.Config.Checksum != nil {
		actual := ComputeSHA256(configFetched.Data)
		if actual != svc.Config.Checksum.Value {
			return FetchedConfig{}, fmt.Errorf(
				"config checksum mismatch for %s: manifest expects %s %s, got %s",
				ms.serviceName, svc.Config.Checksum.Algorithm,
				svc.Config.Checksum.Value, actual,
			)
		}
		ms.logger.Debug("config checksum verified",
			"service", ms.serviceName,
			"algorithm", svc.Config.Checksum.Algorithm,
		)
	}

	ms.mu.Lock()
	ms.lastVersion = svc.Version
	ms.lastCksum = cksum
	ms.mu.Unlock()

	ms.logger.Info("config resolved via manifest",
		"service", ms.serviceName,
		"version", svc.Version,
		"provider", svc.Config.Provider,
	)

	return FetchedConfig{
		Data: configFetched.Data,
		ETag: syntheticETag,
	}, nil
}

// resolveSource builds (or reuses) a ConfigSource for the given resource.
func (ms *ManifestSource) resolveSource(cr *ConfigResource) (ConfigSource, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if ms.resolvedSrc != nil && ms.resolvedCR != nil && configResourceEqual(ms.resolvedCR, cr) {
		return ms.resolvedSrc, nil
	}

	src, err := buildSourceFromResource(cr, &ms.auth, ms.logger)
	if err != nil {
		return nil, err
	}

	ms.resolvedSrc = src
	ms.resolvedCR = cr
	return src, nil
}

// buildSourceFromResource maps a manifest ConfigResource to a ConfigSource
// using the declared provider.
func buildSourceFromResource(cr *ConfigResource, auth *ycloud.AuthConfig, logger *slog.Logger) (ConfigSource, error) {
	switch cr.Provider {
	case "file":
		return NewFileSource(cr.Path), nil

	case "s3":
		endpoint := cr.Endpoint
		if endpoint == "" {
			endpoint = "https://storage.yandexcloud.net"
		}
		region := cr.Region
		if region == "" {
			region = "ru-central1"
		}

		client, err := s3store.NewClient(&s3store.Config{
			Bucket:   cr.Bucket,
			Endpoint: endpoint,
			Region:   region,
			Auth:     *auth,
		}, logger)
		if err != nil {
			return nil, fmt.Errorf("creating S3 client for manifest resource: %w", err)
		}
		return NewS3Source(client, cr.Path), nil

	case "http":
		url := cr.Path
		if cr.Endpoint != "" {
			url = cr.Endpoint + cr.Path
		}
		return NewHTTPSource(url, cr.Headers, nil), nil

	default:
		return nil, fmt.Errorf("unsupported manifest config provider %q", cr.Provider)
	}
}

// configResourceEqual checks if two ConfigResource values point to the same
// underlying asset (used to decide whether to rebuild the resolved source).
func configResourceEqual(a, b *ConfigResource) bool {
	if a.Provider != b.Provider || a.Path != b.Path {
		return false
	}
	if a.Bucket != b.Bucket || a.Region != b.Region || a.Endpoint != b.Endpoint {
		return false
	}
	return true
}
