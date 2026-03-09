package httpx

import (
	"net/http"
	"testing"
)

func TestParseSameSite(t *testing.T) {
	tests := []struct {
		input string
		want  http.SameSite
	}{
		{"strict", http.SameSiteStrictMode},
		{"Strict", http.SameSiteStrictMode},
		{"STRICT", http.SameSiteStrictMode},
		{"none", http.SameSiteNoneMode},
		{"None", http.SameSiteNoneMode},
		{"lax", http.SameSiteLaxMode},
		{"Lax", http.SameSiteLaxMode},
		{"", http.SameSiteLaxMode},
		{"unknown", http.SameSiteLaxMode},
	}
	for _, tt := range tests {
		got := ParseSameSite(tt.input)
		if got != tt.want {
			t.Errorf("ParseSameSite(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAppendQuery(t *testing.T) {
	tests := []struct {
		base string
		kvs  []string
		want string
	}{
		{
			"https://example.com",
			[]string{"error", "conflict"},
			"https://example.com?error=conflict",
		},
		{
			"https://example.com?existing=1",
			[]string{"new", "2"},
			"https://example.com?existing=1&new=2",
		},
		{
			"https://example.com",
			[]string{"a", "1", "b", "2"},
			"https://example.com?a=1&b=2",
		},
		{
			"https://example.com",
			nil,
			"https://example.com",
		},
		{
			"://bad-url",
			[]string{"k", "v"},
			"://bad-url",
		},
	}
	for _, tt := range tests {
		got := AppendQuery(tt.base, tt.kvs...)
		if got != tt.want {
			t.Errorf("AppendQuery(%q, %v) = %q, want %q", tt.base, tt.kvs, got, tt.want)
		}
	}
}
