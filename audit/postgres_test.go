package audit

import (
	"testing"
	"time"
)

func TestCursorRoundTrip(t *testing.T) {
	ts := time.Date(2026, 3, 18, 12, 0, 0, 123456789, time.UTC)
	id := "abc-123-def"

	encoded := encodeCursor(ts, id)
	if encoded == "" {
		t.Fatal("encoded cursor is empty")
	}

	decodedTime, decodedID, err := decodeCursor(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !decodedTime.Equal(ts) {
		t.Errorf("time mismatch: got %v, want %v", decodedTime, ts)
	}
	if decodedID != id {
		t.Errorf("id mismatch: got %q, want %q", decodedID, id)
	}
}

func TestDecodeCursor_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		cursor string
	}{
		{"empty", ""},
		{"not base64", "!!!"},
		{"no pipe", "bm9waXBl"},
		{"bad time", "YmFkdGltZXxhYmM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeCursor(tt.cursor)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestNullableJSON(t *testing.T) {
	if v := nullableJSON(nil); v != nil {
		t.Errorf("expected nil for nil input, got %v", v)
	}
	if v := nullableJSON([]byte{}); v != nil {
		t.Errorf("expected nil for empty input, got %v", v)
	}
	data := []byte(`{"key":"value"}`)
	if v := nullableJSON(data); v == nil {
		t.Error("expected non-nil for valid JSON")
	}
}
