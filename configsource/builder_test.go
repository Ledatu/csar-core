package configsource

import (
	"log/slog"
	"os"
	"testing"
)

func TestBuildSource_File(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	src, err := BuildSource(&SourceParams{
		Source: "file",
		File:   "/tmp/nonexistent.yaml",
	}, logger)
	if err != nil {
		t.Fatalf("BuildSource(file) error: %v", err)
	}
	if src == nil {
		t.Fatal("BuildSource(file) returned nil source")
	}
}

func TestBuildSource_FileRequiresPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	_, err := BuildSource(&SourceParams{
		Source: "file",
	}, logger)
	if err == nil {
		t.Fatal("BuildSource(file) should require a file path")
	}
}

func TestBuildSource_S3RequiresBucket(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	_, err := BuildSource(&SourceParams{
		Source: "s3",
	}, logger)
	if err == nil {
		t.Fatal("BuildSource(s3) should require a bucket")
	}
}

func TestBuildSource_HTTPRequiresURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	_, err := BuildSource(&SourceParams{
		Source: "http",
	}, logger)
	if err == nil {
		t.Fatal("BuildSource(http) should require a URL")
	}
}

func TestBuildSource_HTTP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	src, err := BuildSource(&SourceParams{
		Source:  "http",
		HTTPURL: "https://example.com/config.yaml",
		HTTPHeaders: map[string]string{
			"Authorization": "Bearer tok",
		},
	}, logger)
	if err != nil {
		t.Fatalf("BuildSource(http) error: %v", err)
	}
	if src == nil {
		t.Fatal("BuildSource(http) returned nil source")
	}
}

func TestBuildSource_UnknownSource(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	_, err := BuildSource(&SourceParams{
		Source: "ftp",
	}, logger)
	if err == nil {
		t.Fatal("BuildSource should reject unknown source types")
	}
}
