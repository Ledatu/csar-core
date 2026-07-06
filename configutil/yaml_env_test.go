package configutil

import (
	"os"
	"testing"
	"time"
)

func TestUnmarshalYAMLWithEnv_DurationDefault(t *testing.T) {
	os.Unsetenv("DURATION_VAR")
	t.Cleanup(func() { os.Unsetenv("DURATION_VAR") })

	var cfg struct {
		TTL Duration `yaml:"ttl"`
	}
	if err := UnmarshalYAMLWithEnv([]byte(`ttl: "${DURATION_VAR:-5m}"`), &cfg); err != nil {
		t.Fatalf("UnmarshalYAMLWithEnv() error = %v", err)
	}
	if cfg.TTL.Duration != 5*time.Minute {
		t.Fatalf("TTL = %v, want 5m", cfg.TTL.Duration)
	}
}

func TestUnmarshalYAMLWithEnv_BoolDefault(t *testing.T) {
	os.Unsetenv("BOOL_VAR")
	t.Cleanup(func() { os.Unsetenv("BOOL_VAR") })

	var cfg struct {
		Enabled bool `yaml:"enabled"`
	}
	if err := UnmarshalYAMLWithEnv([]byte(`enabled: "${BOOL_VAR:-true}"`), &cfg); err != nil {
		t.Fatalf("UnmarshalYAMLWithEnv() error = %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("Enabled = false, want true")
	}
}

func TestUnmarshalYAMLWithEnv_IntDefault(t *testing.T) {
	os.Unsetenv("INT_VAR")
	t.Cleanup(func() { os.Unsetenv("INT_VAR") })

	var cfg map[string]any
	if err := UnmarshalYAMLWithEnv([]byte(`count: "${INT_VAR:-42}"`), &cfg); err != nil {
		t.Fatalf("UnmarshalYAMLWithEnv() error = %v", err)
	}
	if cfg["count"] != "42" {
		t.Fatalf("count = %#v, want %q", cfg["count"], "42")
	}
}

func TestUnmarshalYAMLWithEnv_PreservesBackrefs(t *testing.T) {
	var cfg struct {
		Path string `yaml:"path"`
	}
	if err := UnmarshalYAMLWithEnv([]byte(`path: "/backend/$1/items/${HOST:-api.example.com}"`), &cfg); err != nil {
		t.Fatalf("UnmarshalYAMLWithEnv() error = %v", err)
	}
	want := "/backend/$1/items/api.example.com"
	if cfg.Path != want {
		t.Fatalf("Path = %q, want %q", cfg.Path, want)
	}
}

func TestUnmarshalYAMLWithEnv_DoesNotExpandMappingKeys(t *testing.T) {
	os.Unsetenv("FIELD_NAME")
	t.Cleanup(func() { os.Unsetenv("FIELD_NAME") })

	var cfg map[string]string
	if err := UnmarshalYAMLWithEnv([]byte(`"${FIELD_NAME:-ttl}": "5m"`), &cfg); err != nil {
		t.Fatalf("UnmarshalYAMLWithEnv() error = %v", err)
	}
	if cfg["${FIELD_NAME:-ttl}"] != "5m" {
		t.Fatalf("cfg = %#v, want ${FIELD_NAME:-ttl}=5m", cfg)
	}
}
