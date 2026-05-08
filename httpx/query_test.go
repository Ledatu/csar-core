package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/httpx"
)

func TestOptionalBool(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    *bool
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"whitespace", "   ", nil, false},
		{"true", "true", boolPtr(true), false},
		{"false", "false", boolPtr(false), false},
		{"one", "1", boolPtr(true), false},
		{"zero", "0", boolPtr(false), false},
		{"mixed", "True", boolPtr(true), false},
		{"padded", "  true  ", boolPtr(true), false},
		{"invalid", "yes", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := httpx.OptionalBool(tt.in)
			if tt.wantErr && err == nil {
				t.Fatal("want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !samePtr(got, tt.want) {
				t.Fatalf("got %v want %v", deref(got), deref(tt.want))
			}
		})
	}
}

func TestTruthy(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"  ":    false,
		"true":  true,
		"false": false,
		"1":     true,
		"0":     false,
		"yes":   false,
		"TRUE":  true,
		" 1 ":   true,
	}
	for in, want := range cases {
		if got := httpx.Truthy(in); got != want {
			t.Errorf("Truthy(%q)=%v want %v", in, got, want)
		}
	}
}

func TestValues(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, []string{}},
		{"empty-strings", []string{"", "   "}, []string{}},
		{"single", []string{"a"}, []string{"a"}},
		{"comma-separated", []string{"a,b,c"}, []string{"a", "b", "c"}},
		{"mixed", []string{" a , b ", "c,,d"}, []string{"a", "b", "c", "d"}},
		{"many-commas", []string{",,,"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpx.Values(tt.in)
			if !eqStrings(got, tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestParseInt64List(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got, err := httpx.ParseInt64List(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("ok", func(t *testing.T) {
		got, err := httpx.ParseInt64List([]string{"1", "2", "3"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !eqInt64(got, []int64{1, 2, 3}) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("zero rejected", func(t *testing.T) {
		_, err := httpx.ParseInt64List([]string{"0"})
		if err == nil || !strings.Contains(err.Error(), "nm_id must be positive") {
			t.Fatalf("want positive error, got %v", err)
		}
	})
	t.Run("negative rejected", func(t *testing.T) {
		_, err := httpx.ParseInt64List([]string{"-5"})
		if err == nil || !strings.Contains(err.Error(), "nm_id must be positive") {
			t.Fatalf("want positive error, got %v", err)
		}
	})
	t.Run("non-numeric rejected", func(t *testing.T) {
		_, err := httpx.ParseInt64List([]string{"abc"})
		if err == nil {
			t.Fatal("want error")
		}
	})
}

func TestParseLimit(t *testing.T) {
	build := func(v string) *http.Request {
		u := "/items"
		if v != "" {
			u += "?" + v
		}
		return httptest.NewRequest(http.MethodGet, u, http.NoBody)
	}

	t.Run("missing", func(t *testing.T) {
		got, err := httpx.ParseLimit(build(""), 20, 100)
		if err != nil {
			t.Fatal(err)
		}
		if got != 20 {
			t.Fatalf("got %d", got)
		}
	})
	t.Run("empty value", func(t *testing.T) {
		got, err := httpx.ParseLimit(build("limit="), 20, 100)
		if err != nil || got != 20 {
			t.Fatalf("got=%d err=%v", got, err)
		}
	})
	t.Run("whitespace", func(t *testing.T) {
		got, err := httpx.ParseLimit(build("limit=%20%20"), 20, 100)
		if err != nil || got != 20 {
			t.Fatalf("got=%d err=%v", got, err)
		}
	})
	t.Run("non-numeric returns default", func(t *testing.T) {
		got, err := httpx.ParseLimit(build("limit=abc"), 20, 100)
		if err != nil || got != 20 {
			t.Fatalf("got=%d err=%v", got, err)
		}
	})
	t.Run("negative returns default", func(t *testing.T) {
		got, err := httpx.ParseLimit(build("limit=-7"), 20, 100)
		if err != nil || got != 20 {
			t.Fatalf("got=%d err=%v", got, err)
		}
	})
	t.Run("zero returns default", func(t *testing.T) {
		got, err := httpx.ParseLimit(build("limit=0"), 20, 100)
		if err != nil || got != 20 {
			t.Fatalf("got=%d err=%v", got, err)
		}
	})
	t.Run("in range", func(t *testing.T) {
		got, err := httpx.ParseLimit(build("limit=55"), 20, 100)
		if err != nil || got != 55 {
			t.Fatalf("got=%d err=%v", got, err)
		}
	})
	t.Run("over max clamps and errors", func(t *testing.T) {
		got, err := httpx.ParseLimit(build("limit=999"), 20, 100)
		if got != 100 {
			t.Fatalf("got %d want clamped 100", got)
		}
		if err == nil || !strings.Contains(err.Error(), "limit exceeds maximum of 100") {
			t.Fatalf("want exceeds error, got %v", err)
		}
	})
}

func boolPtr(b bool) *bool { return &b }
func deref(p *bool) any {
	if p == nil {
		return nil
	}
	return *p
}
func samePtr(a, b *bool) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func eqInt64(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
