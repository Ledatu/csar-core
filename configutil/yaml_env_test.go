package configutil

import (
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

type strictYAMLFixture struct {
	Enabled bool     `yaml:"enabled"`
	TTL     Duration `yaml:"ttl"`
	Values  []string `yaml:"values"`
}

func (s *strictYAMLFixture) UnmarshalYAML(node *yaml.Node) error {
	type plain strictYAMLFixture
	var decoded plain
	if err := DecodeStrictYAML(node, &decoded); err != nil {
		return err
	}
	*s = strictYAMLFixture(decoded)
	return nil
}

func TestStrictSecuritySectionsPreserveLegacyFields(t *testing.T) {
	t.Setenv("CSAR_TEST_LITERAL", "value\nunknown: true")
	var cfg struct {
		Security *strictYAMLFixture `yaml:"security"`
		Legacy   string             `yaml:"legacy"`
	}
	for _, data := range []string{"", "null", "legacy: works\nold_unknown_field: allowed\n", "defaults: &defaults {legacy: works}\n<<: *defaults\n"} {
		if err := UnmarshalYAMLWithEnvStrictSections([]byte(data), &cfg, "security"); err != nil {
			t.Fatal("legacy declaration failed", err)
		}
	}
	data := "old_unknown_field: allowed\nsecurity:\n  enabled: '${CSAR_TEST_ENABLED:-false}'\n  ttl: '${CSAR_TEST_TTL:-5m}'\n  values: ['${CSAR_TEST_LITERAL}']\n"
	if err := UnmarshalYAMLWithEnvStrictSections([]byte(data), &cfg, "security"); err != nil {
		t.Fatal(err)
	}
	if cfg.Security.Enabled || cfg.Security.TTL.Duration != 5*time.Minute || len(cfg.Security.Values) != 1 || cfg.Security.Values[0] != "value\nunknown: true" {
		t.Fatal("expansion reparsed data or lost scalar types")
	}
}

func TestStrictSecuritySectionsRejectAmbiguity(t *testing.T) {
	for name, data := range map[string]string{
		"null":                   "security: null\n",
		"nonmapping":             "security: []\n",
		"duplicate root key":     "security: {enabled: false}\nsecurity: {enabled: false}\n",
		"unknown key":            "security: {unexpected: secret-do-not-echo}\n",
		"duplicate nested key":   "security: {enabled: false, enabled: true}\n",
		"invalid type":           "security: {enabled: secret-do-not-echo}\n",
		"second document":        "security: {enabled: false}\n---\nsecurity: {enabled: true}\n",
		"later section":          "legacy: works\n---\nsecurity: {enabled: true}\n",
		"trailing garbage":       "security: {enabled: false}\n]\n",
		"whole alias":            "defaults: &defaults {enabled: false}\nsecurity: *defaults\n",
		"nested alias":           "defaults: &defaults [one]\nsecurity: {values: *defaults}\n",
		"nested merge":           "defaults: &defaults {enabled: true}\nsecurity: {<<: *defaults, enabled: false}\n",
		"inherited section":      "defaults: &defaults {security: {enabled: false}}\n<<: *defaults\n",
		"outer merge":            "defaults: &defaults {legacy: works}\n<<: *defaults\nsecurity: {enabled: false}\n",
		"cyclic security":        "security: &cycle {values: [*cycle]}\n",
		"cyclic unrelated alias": "legacy: &cycle [*cycle]\n",
	} {
		t.Run(name, func(t *testing.T) {
			var cfg struct {
				Security *strictYAMLFixture `yaml:"security"`
			}
			err := UnmarshalYAMLWithEnvStrictSections([]byte(data), &cfg, "security")
			if err == nil {
				t.Fatal("ambiguous security configuration accepted")
			}
			if strings.Contains(err.Error(), "secret-do-not-echo") {
				t.Fatal("configured value leaked")
			}
		})
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
