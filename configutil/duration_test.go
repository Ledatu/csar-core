package configutil

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDuration_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"30s", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"1h", time.Hour},
		{"100ms", 100 * time.Millisecond},
		{"2h30m", 2*time.Hour + 30*time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var d Duration
			node := &yaml.Node{Kind: yaml.ScalarNode, Value: tt.input}
			if err := d.UnmarshalYAML(node); err != nil {
				t.Fatalf("UnmarshalYAML(%q) error: %v", tt.input, err)
			}
			if d.Duration != tt.want {
				t.Errorf("got %v, want %v", d.Duration, tt.want)
			}
		})
	}
}

func TestDuration_UnmarshalYAML_Invalid(t *testing.T) {
	var d Duration
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "not-a-duration"}
	if err := d.UnmarshalYAML(node); err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestDuration_MarshalYAML(t *testing.T) {
	d := Duration{Duration: 5 * time.Minute}
	v, err := d.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML error: %v", err)
	}
	if v != "5m0s" {
		t.Errorf("got %q, want %q", v, "5m0s")
	}
}

func TestDuration_Std(t *testing.T) {
	d := Duration{Duration: 10 * time.Second}
	if d.Std() != 10*time.Second {
		t.Errorf("Std() = %v, want %v", d.Std(), 10*time.Second)
	}
}

func TestDuration_RoundTrip(t *testing.T) {
	type wrapper struct {
		TTL Duration `yaml:"ttl"`
	}
	input := "ttl: 24h\n"
	var w wrapper
	if err := yaml.Unmarshal([]byte(input), &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w.TTL.Duration != 24*time.Hour {
		t.Errorf("got %v, want 24h", w.TTL.Duration)
	}

	out, err := yaml.Marshal(&w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != "ttl: 24h0m0s\n" {
		t.Errorf("marshaled: %q", string(out))
	}
}
