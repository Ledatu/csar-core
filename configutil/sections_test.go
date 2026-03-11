package configutil

import (
	"strings"
	"testing"
)

func TestHTTPServerSection_Validate(t *testing.T) {
	tests := []struct {
		name    string
		section HTTPServerSection
		wantErr string
	}{
		{"valid", HTTPServerSection{ListenAddr: ":8080"}, ""},
		{"missing addr", HTTPServerSection{}, "listen_addr is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.section.Validate()
			checkErr(t, err, tt.wantErr)
		})
	}
}

func TestTLSSection_Validate(t *testing.T) {
	tests := []struct {
		name    string
		section TLSSection
		wantErr string
	}{
		{"empty", TLSSection{}, ""},
		{"both set", TLSSection{CertFile: "c.pem", KeyFile: "k.pem"}, ""},
		{"cert only", TLSSection{CertFile: "c.pem"}, "must both be set"},
		{"key only", TLSSection{KeyFile: "k.pem"}, "must both be set"},
		{"valid version 1.2", TLSSection{MinVersion: "1.2"}, ""},
		{"valid version 1.3", TLSSection{MinVersion: "1.3"}, ""},
		{"bad version", TLSSection{MinVersion: "1.1"}, "must be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.section.Validate()
			checkErr(t, err, tt.wantErr)
		})
	}
}

func TestTLSSection_IsEnabled(t *testing.T) {
	if (TLSSection{}).IsEnabled() {
		t.Error("empty section should not be enabled")
	}
	if !(TLSSection{CertFile: "c", KeyFile: "k"}).IsEnabled() {
		t.Error("cert+key should be enabled")
	}
}

func TestDatabaseSection_Validate(t *testing.T) {
	tests := []struct {
		name    string
		section DatabaseSection
		wantErr string
	}{
		{"valid", DatabaseSection{Driver: "postgres", DSN: "host=localhost"}, ""},
		{"no driver", DatabaseSection{DSN: "host=localhost"}, "driver is required"},
		{"no dsn", DatabaseSection{Driver: "postgres"}, "dsn is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.section.Validate()
			checkErr(t, err, tt.wantErr)
		})
	}
}

func TestLogSection_Validate(t *testing.T) {
	tests := []struct {
		name    string
		section LogSection
		wantErr string
	}{
		{"empty", LogSection{}, ""},
		{"info json", LogSection{Level: "info", Format: "json"}, ""},
		{"debug text", LogSection{Level: "debug", Format: "text"}, ""},
		{"bad level", LogSection{Level: "verbose"}, "log.level must be"},
		{"bad format", LogSection{Format: "xml"}, "log.format must be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.section.Validate()
			checkErr(t, err, tt.wantErr)
		})
	}
}

func TestHealthSection_WithDefaults(t *testing.T) {
	s := HealthSection{Enabled: true}
	s = s.WithDefaults()
	if s.LivenessPath != "/health" {
		t.Errorf("LivenessPath = %q, want /health", s.LivenessPath)
	}
	if s.ReadinessPath != "/readiness" {
		t.Errorf("ReadinessPath = %q, want /readiness", s.ReadinessPath)
	}
}

func TestHealthSection_WithDefaults_PreservesCustom(t *testing.T) {
	s := HealthSection{LivenessPath: "/live", ReadinessPath: "/ready"}
	s = s.WithDefaults()
	if s.LivenessPath != "/live" {
		t.Errorf("LivenessPath = %q, want /live", s.LivenessPath)
	}
	if s.ReadinessPath != "/ready" {
		t.Errorf("ReadinessPath = %q, want /ready", s.ReadinessPath)
	}
}

func checkErr(t *testing.T, err error, wantSubstr string) {
	t.Helper()
	if wantSubstr == "" {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Errorf("error %q does not contain %q", err.Error(), wantSubstr)
	}
}
