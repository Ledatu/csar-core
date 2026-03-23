package authzclient

import (
	"log/slog"
	"testing"
)

func TestDial_Insecure(t *testing.T) {
	conn, client, err := Dial(&Config{
		Address:  "localhost:0",
		Insecure: true,
	}, slog.Default())
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

func TestDial_MissingKeyFile(t *testing.T) {
	_, _, err := Dial(&Config{
		Address:  "localhost:0",
		CertFile: "/nonexistent/cert.pem",
	}, slog.Default())
	if err == nil {
		t.Fatal("expected error when CertFile set without KeyFile")
	}
}
