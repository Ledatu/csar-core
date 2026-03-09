package configsource

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
)

type stubSource struct {
	results []FetchedConfig
	idx     int
}

func (s *stubSource) Fetch(_ context.Context) (FetchedConfig, error) {
	if s.idx >= len(s.results) {
		return FetchedConfig{}, fmt.Errorf("no more stub results")
	}
	r := s.results[s.idx]
	s.idx++
	return r, nil
}

func noopApply(_ context.Context, _ []byte) (bool, error) {
	return true, nil
}

func TestApply_SameETagSameBody_Skips(t *testing.T) {
	body := []byte("config: true")
	src := &stubSource{results: []FetchedConfig{
		{Data: body, ETag: "etag-1"},
		{Data: body, ETag: "etag-1"},
	}}

	w := NewConfigWatcher(src, noopApply, slog.Default(), WithHashPolicy(HashTOFU))

	changed, err := w.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first apply should report changed")
	}

	changed, err = w.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("second apply with same ETag + same body should skip")
	}
}

func TestApply_SameETagChangedBody_DetectedByTOFU(t *testing.T) {
	src := &stubSource{results: []FetchedConfig{
		{Data: []byte("config: v1"), ETag: "etag-1"},
		{Data: []byte("config: v2"), ETag: "etag-1"},
	}}

	w := NewConfigWatcher(src, noopApply, slog.Default(), WithHashPolicy(HashTOFU))

	_, err := w.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	_, err = w.Apply(context.Background())
	if err == nil {
		t.Fatal("expected integrity violation error for same ETag + changed body")
	}
}

func TestApply_ChangedETagSameBody_Applies(t *testing.T) {
	body := []byte("config: true")
	applied := 0
	applyFn := func(_ context.Context, _ []byte) (bool, error) {
		applied++
		return true, nil
	}

	src := &stubSource{results: []FetchedConfig{
		{Data: body, ETag: "etag-1"},
		{Data: body, ETag: "etag-2"},
	}}

	w := NewConfigWatcher(src, applyFn, slog.Default(), WithHashPolicy(HashTOFU))

	if _, err := w.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if applied != 2 {
		t.Fatalf("expected 2 applies (changed ETag), got %d", applied)
	}
}

func TestApply_PinnedHash_ValidatedEveryFetch(t *testing.T) {
	body := []byte("config: pinned")
	expectedHash := ComputeSHA256(body)

	src := &stubSource{results: []FetchedConfig{
		{Data: body, ETag: "etag-1"},
		{Data: []byte("config: tampered"), ETag: "etag-2"},
	}}

	w := NewConfigWatcher(src, noopApply, slog.Default(),
		WithHashPolicy(HashPinned),
		WithPinnedHash(expectedHash),
	)

	if _, err := w.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, err := w.Apply(context.Background())
	if err == nil {
		t.Fatal("expected pinned hash mismatch error")
	}
}

func TestApply_NilData_Skips(t *testing.T) {
	src := &stubSource{results: []FetchedConfig{
		{Data: nil, ETag: "etag-1"},
	}}

	w := NewConfigWatcher(src, noopApply, slog.Default())

	changed, err := w.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("nil data should skip")
	}
}
