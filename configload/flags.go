package configload

import (
	"flag"
	"os"
	"strings"
	"time"

	"github.com/ledatu/csar-core/configsource"
)

// SourceFlags groups all flag/env-var configuration for building a
// ConfigSource and its associated watcher. Use NewSourceFlags to create
// one with env-var defaults, then RegisterFlags to wire it into a FlagSet.
type SourceFlags struct {
	Source string

	// File source
	File string

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
	HTTPURL    string
	httpHeader string // raw "key=value,..." parsed by SourceParams()
	httpBearer string // convenience bearer token

	// Manifest source
	ManifestService   string
	ManifestBootstrap string
	ManifestFile      string

	// Watcher
	RefreshInterval string
	HashPolicy      string
	PinnedHash      string
}

// NewSourceFlags returns a SourceFlags populated from environment variables
// with sensible defaults. Call RegisterFlags afterwards to allow CLI flags
// to override these values.
func NewSourceFlags() *SourceFlags {
	return &SourceFlags{
		Source:     EnvOrDefault("CONFIG_SOURCE", "file"),
		File:       EnvOrDefault("CONFIG_FILE", "config.yaml"),
		S3Bucket:   EnvOrDefault("CONFIG_S3_BUCKET", ""),
		S3Key:      EnvOrDefault("CONFIG_S3_KEY", "config.yaml"),
		S3Endpoint: EnvOrDefault("CONFIG_S3_ENDPOINT", "https://storage.yandexcloud.net"),
		S3Region:   EnvOrDefault("CONFIG_S3_REGION", "ru-central1"),
		S3AuthMode: EnvOrDefault("CONFIG_S3_AUTH_MODE", "static"),

		S3AccessKeyID: EnvOrDefault("CONFIG_S3_ACCESS_KEY_ID", ""),
		S3SecretKey:   EnvOrDefault("CONFIG_S3_SECRET_ACCESS_KEY", ""),
		S3IAMToken:    EnvOrDefault("CONFIG_S3_IAM_TOKEN", ""),
		S3OAuthToken:  EnvOrDefault("CONFIG_S3_OAUTH_TOKEN", ""),
		S3SAKeyFile:   EnvOrDefault("CONFIG_S3_SA_KEY_FILE", ""),

		HTTPURL: EnvOrDefault("CONFIG_HTTP_URL", ""),

		ManifestService:   EnvOrDefault("CONFIG_MANIFEST_SERVICE", ""),
		ManifestBootstrap: EnvOrDefault("CONFIG_MANIFEST_BOOTSTRAP", ""),
		ManifestFile:      EnvOrDefault("CONFIG_MANIFEST_FILE", ""),

		RefreshInterval: EnvOrDefault("CONFIG_REFRESH_INTERVAL", "0"),
		HashPolicy:      EnvOrDefault("CONFIG_HASH_POLICY", ""),
		PinnedHash:      EnvOrDefault("CONFIG_PINNED_HASH", ""),
	}
}

// RegisterFlags registers all config-source flags on the given FlagSet.
// Flags override the env-var defaults set by NewSourceFlags.
func (sf *SourceFlags) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&sf.Source, "config-source", sf.Source, `config source type: "file", "s3", "http", or "manifest"`)
	fs.StringVar(&sf.File, "config-file", sf.File, "path to config file (file source)")

	// S3
	fs.StringVar(&sf.S3Bucket, "config-s3-bucket", sf.S3Bucket, "S3 bucket for config")
	fs.StringVar(&sf.S3Key, "config-s3-key", sf.S3Key, "S3 object key for config")
	fs.StringVar(&sf.S3Endpoint, "config-s3-endpoint", sf.S3Endpoint, "S3 endpoint")
	fs.StringVar(&sf.S3Region, "config-s3-region", sf.S3Region, "S3 region")
	fs.StringVar(&sf.S3AuthMode, "config-s3-auth-mode", sf.S3AuthMode, "S3 auth mode: static, iam_token, oauth_token, metadata, service_account")
	fs.StringVar(&sf.S3AccessKeyID, "config-s3-access-key-id", sf.S3AccessKeyID, "S3 access key ID (static auth)")
	fs.StringVar(&sf.S3SecretKey, "config-s3-secret-access-key", sf.S3SecretKey, "S3 secret access key (static auth)")
	fs.StringVar(&sf.S3IAMToken, "config-s3-iam-token", sf.S3IAMToken, "IAM token for S3 (iam_token auth)")
	fs.StringVar(&sf.S3OAuthToken, "config-s3-oauth-token", sf.S3OAuthToken, "OAuth token for S3 (oauth_token auth)")
	fs.StringVar(&sf.S3SAKeyFile, "config-s3-sa-key-file", sf.S3SAKeyFile, "service account key JSON file for S3 (service_account auth)")

	// HTTP
	fs.StringVar(&sf.HTTPURL, "config-url", sf.HTTPURL, "URL to fetch config from (http source)")
	fs.StringVar(&sf.httpHeader, "config-http-header", sf.httpHeader, `extra HTTP headers for config fetch (comma-separated "key=value" pairs)`)
	fs.StringVar(&sf.httpBearer, "config-http-bearer", sf.httpBearer, "bearer token for HTTP config source")

	// Manifest
	fs.StringVar(&sf.ManifestService, "config-manifest-service", sf.ManifestService, "service entry name inside the manifest")
	fs.StringVar(&sf.ManifestBootstrap, "config-manifest-bootstrap", sf.ManifestBootstrap, `bootstrap source for the manifest itself: "file", "s3", "http"`)
	fs.StringVar(&sf.ManifestFile, "config-manifest-file", sf.ManifestFile, "path to manifest file (when bootstrap=file)")

	// Watcher
	fs.StringVar(&sf.RefreshInterval, "config-refresh-interval", sf.RefreshInterval, "config polling interval (e.g. 60s); 0 disables")
	fs.StringVar(&sf.HashPolicy, "config-hash-policy", sf.HashPolicy, `hash validation policy: "tofu" or "pinned"`)
	fs.StringVar(&sf.PinnedHash, "config-pinned-hash", sf.PinnedHash, "expected SHA-256 hash of config (hex); used with pinned policy")
}

// SourceParams converts the flag values into a configsource.SourceParams
// ready for BuildSource. HTTP header/bearer flags are merged into HTTPHeaders.
func (sf *SourceFlags) SourceParams() configsource.SourceParams {
	return configsource.SourceParams{
		Source:              sf.Source,
		File:                sf.File,
		S3Bucket:            sf.S3Bucket,
		S3Key:               sf.S3Key,
		S3Endpoint:          sf.S3Endpoint,
		S3Region:            sf.S3Region,
		S3AuthMode:          sf.S3AuthMode,
		S3AccessKeyID:       sf.S3AccessKeyID,
		S3SecretKey:         sf.S3SecretKey,
		S3IAMToken:          sf.S3IAMToken,
		S3OAuthToken:        sf.S3OAuthToken,
		S3SAKeyFile:         sf.S3SAKeyFile,
		HTTPURL:             sf.HTTPURL,
		HTTPHeaders:         sf.parseHTTPHeaders(),
		ManifestServiceName: sf.ManifestService,
		ManifestBootstrap:   sf.ManifestBootstrap,
		ManifestFile:        sf.ManifestFile,
	}
}

// ParseRefreshInterval returns the refresh interval as a time.Duration.
// Returns 0 if the value is empty, "0", or unparseable.
func (sf *SourceFlags) ParseRefreshInterval() time.Duration {
	return ParseInterval(sf.RefreshInterval)
}

// WatcherOptions returns configsource.WatcherOption values derived from
// the HashPolicy and PinnedHash fields.
func (sf *SourceFlags) WatcherOptions() []configsource.WatcherOption {
	var opts []configsource.WatcherOption
	switch sf.HashPolicy {
	case "pinned":
		opts = append(opts, configsource.WithHashPolicy(configsource.HashPinned))
		if sf.PinnedHash != "" {
			opts = append(opts, configsource.WithPinnedHash(sf.PinnedHash))
		}
	case "tofu", "":
		opts = append(opts, configsource.WithHashPolicy(configsource.HashTOFU))
	}
	return opts
}

func (sf *SourceFlags) parseHTTPHeaders() map[string]string {
	headers := make(map[string]string)
	if sf.httpBearer != "" {
		headers["Authorization"] = "Bearer " + sf.httpBearer
	}
	if sf.httpHeader != "" {
		for _, pair := range strings.Split(sf.httpHeader, ",") {
			pair = strings.TrimSpace(pair)
			if k, v, ok := strings.Cut(pair, "="); ok {
				headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return headers
}

// EnvOrDefault returns the value of the named environment variable, or
// defaultVal if unset or empty.
func EnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// ParseInterval parses a duration string (e.g. "60s"). Returns 0 if the
// string is empty, "0", or cannot be parsed.
func ParseInterval(s string) time.Duration {
	if s == "" || s == "0" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
