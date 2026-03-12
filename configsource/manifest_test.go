package configsource

import (
	"encoding/json"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func validManifestJSON(t *testing.T) []byte {
	t.Helper()
	m := map[string]any{
		"manifest_version": "1",
		"environment":      "test",
		"updated_at":       "2026-03-12T00:00:00Z",
		"trace_id":         "ci-abc-123",
		"services": map[string]any{
			"csar-router": map[string]any{
				"version": "v42",
				"active":  true,
				"config": map[string]any{
					"provider": "s3",
					"bucket":   "my-bucket",
					"region":   "ru-central1",
					"path":     "services/router/v42/config.yaml",
					"checksum": map[string]any{
						"algorithm": "sha256",
						"value":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
			"csar-authn": map[string]any{
				"version": "v12",
				"config": map[string]any{
					"provider": "file",
					"path":     "/etc/csar/authn.yaml",
				},
			},
		},
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseManifest_Valid(t *testing.T) {
	m, err := ParseManifest(validManifestJSON(t))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.ManifestVersion != "1" {
		t.Errorf("ManifestVersion = %q, want %q", m.ManifestVersion, "1")
	}
	if m.Environment != "test" {
		t.Errorf("Environment = %q, want %q", m.Environment, "test")
	}
	if m.TraceID != "ci-abc-123" {
		t.Errorf("TraceID = %q, want %q", m.TraceID, "ci-abc-123")
	}
	if len(m.Services) != 2 {
		t.Errorf("len(Services) = %d, want 2", len(m.Services))
	}

	router, ok := m.Services["csar-router"]
	if !ok {
		t.Fatal("missing csar-router entry")
	}
	if router.Version != "v42" {
		t.Errorf("router.Version = %q, want %q", router.Version, "v42")
	}
	if router.Config.Provider != "s3" {
		t.Errorf("router.Config.Provider = %q, want %q", router.Config.Provider, "s3")
	}
	if router.Config.Bucket != "my-bucket" {
		t.Errorf("router.Config.Bucket = %q, want %q", router.Config.Bucket, "my-bucket")
	}
	if router.Config.Checksum == nil {
		t.Fatal("router.Config.Checksum is nil")
	}
	if router.Config.Checksum.Algorithm != "sha256" {
		t.Errorf("checksum.Algorithm = %q, want %q", router.Config.Checksum.Algorithm, "sha256")
	}
}

func TestParseManifest_AllVersions(t *testing.T) {
	for _, ver := range []string{"1", "1.0", "1.1"} {
		data, _ := json.Marshal(map[string]any{
			"manifest_version": ver,
			"services": map[string]any{
				"svc": map[string]any{
					"version": "v1",
					"config":  map[string]any{"provider": "file", "path": "/x"},
				},
			},
		})
		if _, err := ParseManifest(data); err != nil {
			t.Errorf("ParseManifest(version=%q): %v", ver, err)
		}
	}
}

func TestParseManifest_UnsupportedVersion(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"manifest_version": "99",
		"services": map[string]any{
			"svc": map[string]any{
				"version": "v1",
				"config":  map[string]any{"provider": "file", "path": "/x"},
			},
		},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestParseManifest_EmptyServices(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"manifest_version": "1",
		"services":         map[string]any{},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatal("expected error for empty services")
	}
}

func TestParseManifest_MissingVersion(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"manifest_version": "1",
		"services": map[string]any{
			"svc": map[string]any{
				"config": map[string]any{"provider": "file", "path": "/x"},
			},
		},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatal("expected error for missing service version")
	}
}

func TestParseManifest_InvalidJSON(t *testing.T) {
	if _, err := ParseManifest([]byte(`{not json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseManifest_MissingProvider(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"manifest_version": "1",
		"services": map[string]any{
			"svc": map[string]any{
				"version": "v1",
				"config":  map[string]any{"path": "/x"},
			},
		},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatal("expected error for missing provider")
	}
}

func TestParseManifest_UnsupportedProvider(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"manifest_version": "1",
		"services": map[string]any{
			"svc": map[string]any{
				"version": "v1",
				"config":  map[string]any{"provider": "vault", "path": "/x"},
			},
		},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

func TestLookupService_Found(t *testing.T) {
	m, err := ParseManifest(validManifestJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := m.LookupService("csar-authn")
	if err != nil {
		t.Fatalf("LookupService: %v", err)
	}
	if svc.Version != "v12" {
		t.Errorf("Version = %q, want %q", svc.Version, "v12")
	}
}

func TestLookupService_NotFound(t *testing.T) {
	m, err := ParseManifest(validManifestJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.LookupService("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing service")
	}
}

func TestLookupService_Inactive(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"manifest_version": "1",
		"services": map[string]any{
			"disabled-svc": map[string]any{
				"version": "v1",
				"active":  false,
				"config":  map[string]any{"provider": "file", "path": "/x"},
			},
		},
	})
	m, err := ParseManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.LookupService("disabled-svc")
	if err == nil {
		t.Fatal("expected error for inactive service")
	}
}

func TestIsActive(t *testing.T) {
	tests := []struct {
		name   string
		active *bool
		want   bool
	}{
		{"nil (default true)", nil, true},
		{"explicit true", boolPtr(true), true},
		{"explicit false", boolPtr(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := ServiceManifest{Active: tt.active}
			if got := sm.IsActive(); got != tt.want {
				t.Errorf("IsActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigResource_Validate_S3(t *testing.T) {
	cr := ConfigResource{Provider: "s3", Bucket: "b", Path: "k"}
	if err := cr.Validate(); err != nil {
		t.Fatalf("valid S3: %v", err)
	}

	cr = ConfigResource{Provider: "s3", Path: "k"}
	if err := cr.Validate(); err == nil {
		t.Fatal("S3 without bucket should fail")
	}

	cr = ConfigResource{Provider: "s3", Bucket: "b"}
	if err := cr.Validate(); err == nil {
		t.Fatal("S3 without path should fail")
	}
}

func TestConfigResource_Validate_File(t *testing.T) {
	cr := ConfigResource{Provider: "file", Path: "/etc/config.yaml"}
	if err := cr.Validate(); err != nil {
		t.Fatalf("valid file: %v", err)
	}

	cr = ConfigResource{Provider: "file"}
	if err := cr.Validate(); err == nil {
		t.Fatal("file without path should fail")
	}
}

func TestConfigResource_Validate_HTTP(t *testing.T) {
	cr := ConfigResource{Provider: "http", Path: "https://example.com/config.yaml"}
	if err := cr.Validate(); err != nil {
		t.Fatalf("valid HTTP: %v", err)
	}

	cr = ConfigResource{Provider: "http"}
	if err := cr.Validate(); err == nil {
		t.Fatal("HTTP without path should fail")
	}
}

func TestConfigResource_Validate_Checksum(t *testing.T) {
	cr := ConfigResource{
		Provider: "file",
		Path:     "/x",
		Checksum: &ChecksumInfo{Algorithm: "sha256", Value: "abc123"},
	}
	if err := cr.Validate(); err != nil {
		t.Fatalf("valid checksum: %v", err)
	}

	cr.Checksum = &ChecksumInfo{Algorithm: "", Value: "abc123"}
	if err := cr.Validate(); err == nil {
		t.Fatal("checksum without algorithm should fail")
	}

	cr.Checksum = &ChecksumInfo{Algorithm: "sha256", Value: ""}
	if err := cr.Validate(); err == nil {
		t.Fatal("checksum without value should fail")
	}

	cr.Checksum = &ChecksumInfo{Algorithm: "md5", Value: "abc123"}
	if err := cr.Validate(); err == nil {
		t.Fatal("unsupported checksum algorithm should fail")
	}
}
