package configload

import (
	"context"
	"flag"
	"testing"

	"github.com/ledatu/csar-core/configsource"
)

func TestNewSourceFlags_Defaults(t *testing.T) {
	sf := NewSourceFlags()
	if sf.Source != "file" {
		t.Fatalf("Source = %q, want file", sf.Source)
	}
	if sf.File != "config.yaml" {
		t.Fatalf("File = %q, want config.yaml", sf.File)
	}
	if sf.S3Key != "config.yaml" {
		t.Fatalf("S3Key = %q, want config.yaml", sf.S3Key)
	}
	if sf.S3Endpoint != "https://storage.yandexcloud.net" {
		t.Fatalf("S3Endpoint = %q, want https://storage.yandexcloud.net", sf.S3Endpoint)
	}
	if sf.S3Region != "ru-central1" {
		t.Fatalf("S3Region = %q, want ru-central1", sf.S3Region)
	}
	if sf.S3AuthMode != "static" {
		t.Fatalf("S3AuthMode = %q, want static", sf.S3AuthMode)
	}
	if sf.RefreshInterval != "0" {
		t.Fatalf("RefreshInterval = %q, want 0", sf.RefreshInterval)
	}
}

func TestNewSourceFlags_EnvOverride(t *testing.T) {
	t.Setenv("CONFIG_SOURCE", "s3")
	t.Setenv("CONFIG_S3_BUCKET", "my-bucket")
	t.Setenv("CONFIG_MANIFEST_SERVICE", "my-svc")

	sf := NewSourceFlags()
	if sf.Source != "s3" {
		t.Fatalf("Source = %q, want s3", sf.Source)
	}
	if sf.S3Bucket != "my-bucket" {
		t.Fatalf("S3Bucket = %q, want my-bucket", sf.S3Bucket)
	}
	if sf.ManifestService != "my-svc" {
		t.Fatalf("ManifestService = %q, want my-svc", sf.ManifestService)
	}
}

func TestRegisterFlags_Overrides(t *testing.T) {
	sf := NewSourceFlags()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	sf.RegisterFlags(fs)

	err := fs.Parse([]string{
		"-config-source", "manifest",
		"-config-file", "/tmp/test.yaml",
		"-config-manifest-service", "csar-authn",
		"-config-manifest-bootstrap", "file",
		"-config-manifest-file", "/etc/manifest.json",
		"-config-url", "https://example.com/config",
		"-config-http-bearer", "tok123",
		"-config-refresh-interval", "30s",
		"-config-hash-policy", "pinned",
		"-config-pinned-hash", "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}

	if sf.Source != "manifest" {
		t.Fatalf("Source = %q, want manifest", sf.Source)
	}
	if sf.File != "/tmp/test.yaml" {
		t.Fatalf("File = %q, want /tmp/test.yaml", sf.File)
	}
	if sf.ManifestService != "csar-authn" {
		t.Fatalf("ManifestService = %q, want csar-authn", sf.ManifestService)
	}
	if sf.ManifestBootstrap != "file" {
		t.Fatalf("ManifestBootstrap = %q, want file", sf.ManifestBootstrap)
	}
	if sf.ManifestFile != "/etc/manifest.json" {
		t.Fatalf("ManifestFile = %q, want /etc/manifest.json", sf.ManifestFile)
	}
	if sf.HTTPURL != "https://example.com/config" {
		t.Fatalf("HTTPURL = %q, want https://example.com/config", sf.HTTPURL)
	}
	if sf.RefreshInterval != "30s" {
		t.Fatalf("RefreshInterval = %q, want 30s", sf.RefreshInterval)
	}
	if sf.HashPolicy != "pinned" {
		t.Fatalf("HashPolicy = %q, want pinned", sf.HashPolicy)
	}
	if sf.PinnedHash != "abc123" {
		t.Fatalf("PinnedHash = %q, want abc123", sf.PinnedHash)
	}
}

func TestSourceParams_Basic(t *testing.T) {
	sf := &SourceFlags{
		Source:            "s3",
		File:              "config.yaml",
		S3Bucket:          "bucket",
		S3Key:             "key.yaml",
		ManifestService:   "svc",
		ManifestBootstrap: "file",
		ManifestFile:      "/m.json",
	}

	p := sf.SourceParams()
	if p.Source != "s3" {
		t.Fatalf("Source = %q, want s3", p.Source)
	}
	if p.S3Bucket != "bucket" {
		t.Fatalf("S3Bucket = %q, want bucket", p.S3Bucket)
	}
	if p.ManifestServiceName != "svc" {
		t.Fatalf("ManifestServiceName = %q, want svc", p.ManifestServiceName)
	}
	if p.ManifestBootstrap != "file" {
		t.Fatalf("ManifestBootstrap = %q, want file", p.ManifestBootstrap)
	}
	if p.ManifestFile != "/m.json" {
		t.Fatalf("ManifestFile = %q, want /m.json", p.ManifestFile)
	}
}

func TestSourceParams_HTTPHeaders(t *testing.T) {
	sf := &SourceFlags{
		Source:     "http",
		HTTPURL:    "https://example.com/cfg",
		httpBearer: "mytoken",
		httpHeader: "X-Custom=val1, X-Other=val2",
	}

	p := sf.SourceParams()
	if p.HTTPHeaders["Authorization"] != "Bearer mytoken" {
		t.Fatalf("Authorization = %q, want Bearer mytoken", p.HTTPHeaders["Authorization"])
	}
	if p.HTTPHeaders["X-Custom"] != "val1" {
		t.Fatalf("X-Custom = %q, want val1", p.HTTPHeaders["X-Custom"])
	}
	if p.HTTPHeaders["X-Other"] != "val2" {
		t.Fatalf("X-Other = %q, want val2", p.HTTPHeaders["X-Other"])
	}
}

func TestSourceParams_HTTPHeadersEmpty(t *testing.T) {
	sf := &SourceFlags{Source: "http", HTTPURL: "https://example.com/cfg"}
	p := sf.SourceParams()
	if len(p.HTTPHeaders) != 0 {
		t.Fatalf("expected empty headers, got %v", p.HTTPHeaders)
	}
}

func TestParseRefreshInterval(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"60s", "1m0s"},
		{"0", "0s"},
		{"", "0s"},
		{"invalid", "0s"},
		{"30s", "30s"},
	}
	for _, tc := range tests {
		sf := &SourceFlags{RefreshInterval: tc.input}
		got := sf.ParseRefreshInterval().String()
		if got != tc.want {
			t.Errorf("ParseRefreshInterval(%q) = %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestWatcherOptions_TOFU(t *testing.T) {
	sf := &SourceFlags{HashPolicy: "tofu"}
	opts := sf.WatcherOptions()
	if len(opts) != 1 {
		t.Fatalf("len(opts) = %d, want 1", len(opts))
	}
}

func TestWatcherOptions_Pinned(t *testing.T) {
	sf := &SourceFlags{HashPolicy: "pinned", PinnedHash: "deadbeef"}
	opts := sf.WatcherOptions()
	if len(opts) != 2 {
		t.Fatalf("len(opts) = %d, want 2 (policy + hash)", len(opts))
	}
}

func TestWatcherOptions_PinnedNoHash(t *testing.T) {
	sf := &SourceFlags{HashPolicy: "pinned"}
	opts := sf.WatcherOptions()
	if len(opts) != 1 {
		t.Fatalf("len(opts) = %d, want 1", len(opts))
	}
}

func TestWatcherOptions_Empty(t *testing.T) {
	sf := &SourceFlags{HashPolicy: ""}
	opts := sf.WatcherOptions()
	if len(opts) != 1 {
		t.Fatalf("len(opts) = %d, want 1 (default TOFU)", len(opts))
	}
}

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("TEST_FLAG_KEY", "env_val")
	if got := EnvOrDefault("TEST_FLAG_KEY", "default"); got != "env_val" {
		t.Fatalf("got %q, want env_val", got)
	}
	if got := EnvOrDefault("TEST_FLAG_KEY_NONEXISTENT", "fallback"); got != "fallback" {
		t.Fatalf("got %q, want fallback", got)
	}
}

func TestParseInterval(t *testing.T) {
	if d := ParseInterval("30s"); d.String() != "30s" {
		t.Fatalf("got %s, want 30s", d)
	}
	if d := ParseInterval("0"); d != 0 {
		t.Fatalf("got %s, want 0", d)
	}
	if d := ParseInterval(""); d != 0 {
		t.Fatalf("got %s, want 0", d)
	}
	if d := ParseInterval("bad"); d != 0 {
		t.Fatalf("got %s, want 0", d)
	}
}

func TestSourceFlags_RegisterAndParse_HTTPBearer(t *testing.T) {
	sf := NewSourceFlags()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	sf.RegisterFlags(fs)

	err := fs.Parse([]string{
		"-config-source", "http",
		"-config-url", "https://cfg.example.com",
		"-config-http-bearer", "secret-token",
		"-config-http-header", "X-Env=prod",
	})
	if err != nil {
		t.Fatal(err)
	}

	p := sf.SourceParams()
	if p.HTTPURL != "https://cfg.example.com" {
		t.Fatalf("HTTPURL = %q", p.HTTPURL)
	}
	if p.HTTPHeaders["Authorization"] != "Bearer secret-token" {
		t.Fatalf("Authorization = %q", p.HTTPHeaders["Authorization"])
	}
	if p.HTTPHeaders["X-Env"] != "prod" {
		t.Fatalf("X-Env = %q", p.HTTPHeaders["X-Env"])
	}
}

// Verify WatcherOptions produce valid options by applying them to a real watcher.
func TestWatcherOptions_Functional(t *testing.T) {
	sf := &SourceFlags{HashPolicy: "pinned", PinnedHash: "abc"}
	opts := sf.WatcherOptions()

	src := &staticSource{data: []byte("data"), etag: "v1"}
	w := configsource.NewConfigWatcher(
		src,
		func(_ context.Context, _ []byte) (bool, error) { return true, nil },
		nil,
		opts...,
	)
	_ = w
}
