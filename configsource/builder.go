package configsource

import (
	"fmt"
	"log/slog"

	"github.com/ledatu/csar-core/s3store"
	"github.com/ledatu/csar-core/secret"
	"github.com/ledatu/csar-core/ycloud"
)

// SourceParams holds the flags/env vars needed to build a ConfigSource.
// Supported source types: "file", "s3", "http", "manifest".
type SourceParams struct {
	Source string // "file", "s3", "http", or "manifest"

	// File source
	File string // path for file source

	// S3 source
	S3Bucket      string
	S3Key         string
	S3Endpoint    string
	S3Region      string
	S3AuthMode    string
	S3AccessKeyID string
	S3SecretKey   string
	S3IAMToken    string
	S3OAuthToken  string
	S3SAKeyFile   string

	// HTTP source
	HTTPURL     string
	HTTPHeaders map[string]string

	// Manifest source
	ManifestServiceName string // service entry to resolve inside the manifest
	ManifestBootstrap   string // bootstrap source type for the manifest itself: "file", "s3", "http"
	ManifestFile        string // path to manifest file (when ManifestBootstrap="file")
}

// BuildSource creates a ConfigSource from the given params.
func BuildSource(p *SourceParams, logger *slog.Logger) (ConfigSource, error) {
	switch p.Source {
	case "file":
		if p.File == "" {
			return nil, fmt.Errorf("file path is required for file config source")
		}
		logger.Info("config source: file", "path", p.File)
		return NewFileSource(p.File), nil

	case "s3":
		if p.S3Bucket == "" {
			return nil, fmt.Errorf("S3 bucket is required for s3 config source")
		}
		client, err := s3store.NewClient(&s3store.Config{
			Bucket:   p.S3Bucket,
			Endpoint: p.S3Endpoint,
			Region:   p.S3Region,
			Auth: ycloud.AuthConfig{
				AuthMode:        p.S3AuthMode,
				IAMToken:        secret.NewSecret(p.S3IAMToken),
				OAuthToken:      secret.NewSecret(p.S3OAuthToken),
				SAKeyFile:       p.S3SAKeyFile,
				AccessKeyID:     secret.NewSecret(p.S3AccessKeyID),
				SecretAccessKey: secret.NewSecret(p.S3SecretKey),
			},
		}, logger)
		if err != nil {
			return nil, fmt.Errorf("creating S3 client: %w", err)
		}
		logger.Info("config source: s3", "bucket", p.S3Bucket, "key", p.S3Key)
		return NewS3Source(client, p.S3Key), nil

	case "http":
		if p.HTTPURL == "" {
			return nil, fmt.Errorf("URL is required for http config source")
		}
		logger.Info("config source: http", "url", p.HTTPURL)
		return NewHTTPSource(p.HTTPURL, p.HTTPHeaders, nil), nil

	case "manifest":
		if p.ManifestServiceName == "" {
			return nil, fmt.Errorf("service name is required for manifest config source")
		}

		bootstrapSource := p.ManifestBootstrap
		if bootstrapSource == "" {
			return nil, fmt.Errorf("manifest bootstrap source type is required (file, s3, http)")
		}

		bootstrapParams := &SourceParams{Source: bootstrapSource}
		switch bootstrapSource {
		case "file":
			if p.ManifestFile == "" {
				return nil, fmt.Errorf("manifest file path is required when manifest bootstrap is file")
			}
			bootstrapParams.File = p.ManifestFile
		case "s3":
			bootstrapParams.S3Bucket = p.S3Bucket
			bootstrapParams.S3Key = p.S3Key
			bootstrapParams.S3Endpoint = p.S3Endpoint
			bootstrapParams.S3Region = p.S3Region
			bootstrapParams.S3AuthMode = p.S3AuthMode
			bootstrapParams.S3AccessKeyID = p.S3AccessKeyID
			bootstrapParams.S3SecretKey = p.S3SecretKey
			bootstrapParams.S3IAMToken = p.S3IAMToken
			bootstrapParams.S3OAuthToken = p.S3OAuthToken
			bootstrapParams.S3SAKeyFile = p.S3SAKeyFile
		case "http":
			bootstrapParams.HTTPURL = p.HTTPURL
			bootstrapParams.HTTPHeaders = p.HTTPHeaders
		default:
			return nil, fmt.Errorf("unsupported manifest bootstrap source %q; supported: file, s3, http", bootstrapSource)
		}

		bootstrap, err := BuildSource(bootstrapParams, logger)
		if err != nil {
			return nil, fmt.Errorf("building manifest bootstrap source: %w", err)
		}

		auth := s3AuthFromParams(p)
		logger.Info("config source: manifest",
			"bootstrap", bootstrapSource,
			"service", p.ManifestServiceName,
		)
		return NewManifestSource(bootstrap, p.ManifestServiceName, &auth, logger), nil

	default:
		return nil, fmt.Errorf("unknown config source %q; supported: file, s3, http, manifest", p.Source)
	}
}

// s3AuthFromParams extracts the S3/Yandex Cloud auth configuration from
// SourceParams. Used by the manifest source to pass inherited credentials
// to resolved S3-provider config resources.
func s3AuthFromParams(p *SourceParams) ycloud.AuthConfig {
	return ycloud.AuthConfig{
		AuthMode:        p.S3AuthMode,
		IAMToken:        secret.NewSecret(p.S3IAMToken),
		OAuthToken:      secret.NewSecret(p.S3OAuthToken),
		SAKeyFile:       p.S3SAKeyFile,
		AccessKeyID:     secret.NewSecret(p.S3AccessKeyID),
		SecretAccessKey: secret.NewSecret(p.S3SecretKey),
	}
}
