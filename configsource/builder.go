package configsource

import (
	"fmt"
	"log/slog"

	"github.com/Ledatu/csar-core/s3store"
	"github.com/Ledatu/csar-core/secret"
	"github.com/Ledatu/csar-core/ycloud"
)

// SourceParams holds the flags/env vars needed to build a ConfigSource.
// Supported source types: "file", "s3", "http".
type SourceParams struct {
	Source string // "file", "s3", or "http"

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

	default:
		return nil, fmt.Errorf("unknown config source %q; supported: file, s3, http", p.Source)
	}
}
