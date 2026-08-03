package logutil

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactingHandler_RedactsSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	h := NewRedactingHandler(inner)
	logger := slog.New(h)

	logger.Info("test", "authorization", "Bearer secret123", "user", "alice")

	output := buf.String()
	if strings.Contains(output, "secret123") {
		t.Errorf("output should not contain secret123: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("output should contain [REDACTED]: %s", output)
	}
	if !strings.Contains(output, "alice") {
		t.Errorf("output should contain alice: %s", output)
	}
}

func TestRedactingHandler_SubstringMatch(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	h := NewRedactingHandler(inner)
	logger := slog.New(h)

	logger.Info("test", "iam_token_value", "mysecret")

	output := buf.String()
	if strings.Contains(output, "mysecret") {
		t.Errorf("iam_token_value should be redacted: %s", output)
	}
}

func TestRedactingHandler_GroupRecursion(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	h := NewRedactingHandler(inner)
	logger := slog.New(h)

	logger.Info("test", slog.Group("auth",
		slog.String("password", "secret"),
		slog.String("user", "bob"),
	))

	output := buf.String()
	if strings.Contains(output, "secret") {
		t.Errorf("password in group should be redacted: %s", output)
	}
	if !strings.Contains(output, "bob") {
		t.Errorf("output should contain bob: %s", output)
	}
}

func TestRedactingHandler_NonSensitivePassThrough(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	h := NewRedactingHandler(inner)
	logger := slog.New(h)

	logger.Info("test", "method", "GET", "path", "/api/v1/users")

	output := buf.String()
	if !strings.Contains(output, "GET") {
		t.Errorf("non-sensitive values should pass through: %s", output)
	}
	if !strings.Contains(output, "/api/v1/users") {
		t.Errorf("non-sensitive values should pass through: %s", output)
	}
}

func TestIsSensitiveKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"authorization", true},
		{"Authorization", true},
		{"AUTHORIZATION", true},
		{"X-Csar-Authorization", true},
		{"x-csar-authorization", true},
		{"password", true},
		{"x-api-key", true},
		{"bearer", true},
		{"my_oauth_token", true},
		{"method", false},
		{"path", false},
		{"status", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := IsSensitiveKey(tt.key); got != tt.want {
				t.Errorf("IsSensitiveKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}
