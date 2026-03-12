package configsource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/ledatu/csar-core/ycloud"
)

// mockSource returns configurable results and tracks call count.
type mockSource struct {
	results []FetchedConfig
	errs    []error
	idx     int
}

func (m *mockSource) Fetch(_ context.Context) (FetchedConfig, error) {
	if m.idx >= len(m.results) {
		return FetchedConfig{}, fmt.Errorf("mockSource: no more results (called %d times)", m.idx+1)
	}
	r := m.results[m.idx]
	var err error
	if m.idx < len(m.errs) {
		err = m.errs[m.idx]
	}
	m.idx++
	return r, err
}

func makeManifestJSON(t *testing.T, services map[string]any) []byte {
	t.Helper()
	m := map[string]any{
		"manifest_version": "1",
		"environment":      "test",
		"trace_id":         "test-trace-1",
		"services":         services,
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestManifestSource_FetchResolvesFileProvider(t *testing.T) {
	configBody := []byte("listen_addr: :8080")
	cksum := sha256hex(configBody)

	tmpFile := t.TempDir() + "/config.yaml"
	writeTestFile(t, tmpFile, configBody)

	manifestData := makeManifestJSON(t, map[string]any{
		"my-service": map[string]any{
			"version": "v1",
			"config": map[string]any{
				"provider": "file",
				"path":     tmpFile,
				"checksum": map[string]any{"algorithm": "sha256", "value": cksum},
			},
		},
	})

	bootstrap := &mockSource{results: []FetchedConfig{
		{Data: manifestData, ETag: "manifest-etag-1"},
	}}

	ms := NewManifestSource(bootstrap, "my-service", &ycloud.AuthConfig{}, slog.Default())
	fetched, err := ms.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(fetched.Data, configBody) {
		t.Errorf("Data = %q, want %q", fetched.Data, configBody)
	}
	if fetched.ETag == "" {
		t.Error("ETag should be non-empty")
	}
}

func TestManifestSource_ChecksumMismatch(t *testing.T) {
	configBody := []byte("listen_addr: :8080")
	wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

	tmpFile := t.TempDir() + "/config.yaml"
	writeTestFile(t, tmpFile, configBody)

	manifestData := makeManifestJSON(t, map[string]any{
		"my-service": map[string]any{
			"version": "v1",
			"config": map[string]any{
				"provider": "file",
				"path":     tmpFile,
				"checksum": map[string]any{"algorithm": "sha256", "value": wrongChecksum},
			},
		},
	})

	bootstrap := &mockSource{results: []FetchedConfig{
		{Data: manifestData, ETag: "etag-1"},
	}}

	ms := NewManifestSource(bootstrap, "my-service", &ycloud.AuthConfig{}, slog.Default())
	_, err := ms.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestManifestSource_NoChecksumSkipsValidation(t *testing.T) {
	configBody := []byte("listen_addr: :8080")
	tmpFile := t.TempDir() + "/config.yaml"
	writeTestFile(t, tmpFile, configBody)

	manifestData := makeManifestJSON(t, map[string]any{
		"my-service": map[string]any{
			"version": "v1",
			"config": map[string]any{
				"provider": "file",
				"path":     tmpFile,
			},
		},
	})

	bootstrap := &mockSource{results: []FetchedConfig{
		{Data: manifestData, ETag: "etag-1"},
	}}

	ms := NewManifestSource(bootstrap, "my-service", &ycloud.AuthConfig{}, slog.Default())
	fetched, err := ms.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(fetched.Data, configBody) {
		t.Errorf("Data = %q, want %q", fetched.Data, configBody)
	}
}

func TestManifestSource_VersionChangeTriggersRefetch(t *testing.T) {
	configV1 := []byte("version: v1")
	configV2 := []byte("version: v2")

	dir := t.TempDir()
	fileV1 := dir + "/v1.yaml"
	fileV2 := dir + "/v2.yaml"
	writeTestFile(t, fileV1, configV1)
	writeTestFile(t, fileV2, configV2)

	manifest1 := makeManifestJSON(t, map[string]any{
		"svc": map[string]any{
			"version": "v1",
			"config":  map[string]any{"provider": "file", "path": fileV1},
		},
	})
	manifest2 := makeManifestJSON(t, map[string]any{
		"svc": map[string]any{
			"version": "v2",
			"config":  map[string]any{"provider": "file", "path": fileV2},
		},
	})

	bootstrap := &mockSource{results: []FetchedConfig{
		{Data: manifest1, ETag: "etag-1"},
		{Data: manifest2, ETag: "etag-2"},
	}}

	ms := NewManifestSource(bootstrap, "svc", &ycloud.AuthConfig{}, slog.Default())

	f1, err := ms.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 1: %v", err)
	}
	if !bytes.Equal(f1.Data, configV1) {
		t.Errorf("Fetch 1 Data = %q, want %q", f1.Data, configV1)
	}

	f2, err := ms.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 2: %v", err)
	}
	if !bytes.Equal(f2.Data, configV2) {
		t.Errorf("Fetch 2 Data = %q, want %q", f2.Data, configV2)
	}
}

func TestManifestSource_SameVersionReturnsNilData(t *testing.T) {
	configBody := []byte("version: v1")
	dir := t.TempDir()
	file := dir + "/config.yaml"
	writeTestFile(t, file, configBody)

	manifest := makeManifestJSON(t, map[string]any{
		"svc": map[string]any{
			"version": "v1",
			"config":  map[string]any{"provider": "file", "path": file},
		},
	})

	bootstrap := &mockSource{results: []FetchedConfig{
		{Data: manifest, ETag: "etag-1"},
		{Data: manifest, ETag: "etag-2"},
	}}

	ms := NewManifestSource(bootstrap, "svc", &ycloud.AuthConfig{}, slog.Default())

	_, err := ms.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 1: %v", err)
	}

	f2, err := ms.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 2: %v", err)
	}
	if f2.Data != nil {
		t.Errorf("Fetch 2 should return nil Data for unchanged version, got %d bytes", len(f2.Data))
	}
}

func TestManifestSource_NilBootstrapData(t *testing.T) {
	bootstrap := &mockSource{results: []FetchedConfig{
		{Data: nil, ETag: "etag-1"},
	}}

	ms := NewManifestSource(bootstrap, "svc", &ycloud.AuthConfig{}, slog.Default())
	fetched, err := ms.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fetched.Data != nil {
		t.Error("nil bootstrap data should propagate as nil")
	}
}

func TestManifestSource_BootstrapError(t *testing.T) {
	bootstrap := &mockSource{
		results: []FetchedConfig{{}},
		errs:    []error{fmt.Errorf("network error")},
	}

	ms := NewManifestSource(bootstrap, "svc", &ycloud.AuthConfig{}, slog.Default())
	_, err := ms.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error from bootstrap failure")
	}
}

func TestManifestSource_ServiceNotFound(t *testing.T) {
	manifest := makeManifestJSON(t, map[string]any{
		"other-svc": map[string]any{
			"version": "v1",
			"config":  map[string]any{"provider": "file", "path": "/x"},
		},
	})

	bootstrap := &mockSource{results: []FetchedConfig{
		{Data: manifest, ETag: "etag-1"},
	}}

	ms := NewManifestSource(bootstrap, "missing-svc", &ycloud.AuthConfig{}, slog.Default())
	_, err := ms.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for missing service")
	}
}

func TestManifestSource_HTTPProviderResolution(t *testing.T) {
	manifest := makeManifestJSON(t, map[string]any{
		"svc": map[string]any{
			"version": "v1",
			"config": map[string]any{
				"provider": "http",
				"path":     "https://example.com/config.yaml",
			},
		},
	})

	bootstrap := &mockSource{results: []FetchedConfig{
		{Data: manifest, ETag: "etag-1"},
	}}

	ms := NewManifestSource(bootstrap, "svc", &ycloud.AuthConfig{}, slog.Default())

	// Fetch will fail because the HTTP URL is not reachable, but it should
	// get past manifest resolution to the actual HTTP fetch step.
	_, err := ms.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error from unreachable HTTP endpoint")
	}
	// The error should mention the HTTP fetch, not manifest parsing.
	if _, parseErr := ParseManifest(manifest); parseErr != nil {
		t.Fatalf("manifest itself should be valid: %v", parseErr)
	}
}

func TestBuildSource_Manifest_RequiresServiceName(t *testing.T) {
	logger := slog.Default()
	_, err := BuildSource(&SourceParams{
		Source:            "manifest",
		ManifestBootstrap: "file",
		ManifestFile:      "/tmp/manifest.json",
	}, logger)
	if err == nil {
		t.Fatal("expected error when ManifestServiceName is empty")
	}
}

func TestBuildSource_Manifest_RequiresBootstrap(t *testing.T) {
	logger := slog.Default()
	_, err := BuildSource(&SourceParams{
		Source:              "manifest",
		ManifestServiceName: "svc",
	}, logger)
	if err == nil {
		t.Fatal("expected error when ManifestBootstrap is empty")
	}
}

func TestBuildSource_Manifest_FileBootstrap(t *testing.T) {
	logger := slog.Default()
	src, err := BuildSource(&SourceParams{
		Source:              "manifest",
		ManifestBootstrap:   "file",
		ManifestFile:        "/tmp/manifest.json",
		ManifestServiceName: "svc",
	}, logger)
	if err != nil {
		t.Fatalf("BuildSource(manifest/file): %v", err)
	}
	if src == nil {
		t.Fatal("BuildSource returned nil")
	}
	if _, ok := src.(*ManifestSource); !ok {
		t.Fatalf("expected *ManifestSource, got %T", src)
	}
}

func TestBuildSource_Manifest_UnsupportedBootstrap(t *testing.T) {
	logger := slog.Default()
	_, err := BuildSource(&SourceParams{
		Source:              "manifest",
		ManifestBootstrap:   "ftp",
		ManifestServiceName: "svc",
	}, logger)
	if err == nil {
		t.Fatal("expected error for unsupported bootstrap source")
	}
}

// writeTestFile is a helper that writes data to a file for testing.
func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
