package configload

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/ledatu/csar-core/configsource"
)

type staticSource struct {
	data []byte
	etag string
	err  error
}

func (s *staticSource) Fetch(_ context.Context) (configsource.FetchedConfig, error) {
	return configsource.FetchedConfig{Data: s.data, ETag: s.etag}, s.err
}

func TestLoadInitial_Success(t *testing.T) {
	type cfg struct{ Name string }

	dir := t.TempDir()
	path := dir + "/config.yaml"
	if err := os.WriteFile(path, []byte(`name: "hello"`), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := LoadInitial(context.Background(), &configsource.SourceParams{
		Source: "file",
		File:   path,
	}, slog.Default(), func(data []byte) (*cfg, error) {
		return &cfg{Name: "parsed"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "parsed" {
		t.Fatalf("Name = %q, want parsed", result.Name)
	}
}

func TestLoadInitial_ParseFailure(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.yaml"
	if err := os.WriteFile(path, []byte("some content"), 0644); err != nil {
		t.Fatal(err)
	}

	type cfg struct{}
	_, err := LoadInitial(context.Background(), &configsource.SourceParams{
		Source: "file",
		File:   path,
	}, slog.Default(), func(data []byte) (*cfg, error) {
		return nil, fmt.Errorf("parse error")
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadInitial_BadSource(t *testing.T) {
	type cfg struct{}
	_, err := LoadInitial(context.Background(), &configsource.SourceParams{
		Source: "unknown",
	}, slog.Default(), func(data []byte) (*cfg, error) {
		return &cfg{}, nil
	})
	if err == nil {
		t.Fatal("expected error for unknown source type")
	}
}

func TestNewValidatingWatcher_ValidationFailure(t *testing.T) {
	src := &staticSource{data: []byte("bad config"), etag: "v1"}
	validationErr := errors.New("invalid config")

	watcher := NewValidatingWatcher(src, slog.Default(), func(data []byte) error {
		return validationErr
	})

	changed, err := watcher.Apply(context.Background())
	if err == nil {
		t.Fatal("expected validation error")
	}
	if changed {
		t.Fatal("expected changed=false on validation failure")
	}
}

func TestNewValidatingWatcher_Success(t *testing.T) {
	src := &staticSource{data: []byte("good config"), etag: "v1"}

	watcher := NewValidatingWatcher(src, slog.Default(), func(data []byte) error {
		return nil
	})

	changed, err := watcher.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected changed=false for validate-only watcher")
	}
}

func TestNewValidatingWatcher_NoopOnSameData(t *testing.T) {
	src := &staticSource{data: []byte("stable config"), etag: "v1"}

	watcher := NewValidatingWatcher(src, slog.Default(), func(data []byte) error {
		return nil
	})

	// First apply.
	_, _ = watcher.Apply(context.Background())

	// Second apply with same etag — should be a no-op.
	changed, err := watcher.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected no change on second apply with same data")
	}
}
