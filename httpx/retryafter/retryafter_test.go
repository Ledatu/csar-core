package retryafter

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseBoundedRemoteHints(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{"", 0}, {"0", 0}, {"-1", 0}, {"+1", 0}, {"1.5", 0}, {" 3600 ", time.Hour},
		{"999999999999999999999999999999999999", MaxDelay},
		{strings.Repeat("9", 129), 0}, {"garbage", 0},
		{now.Add(time.Hour).Format(http.TimeFormat), time.Hour},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
		{now.Add(48 * time.Hour).Format(http.TimeFormat), MaxDelay},
	} {
		if got := Parse(tc.raw, now, MaxDelay); got != tc.want {
			t.Errorf("%q: got %s want %s", tc.raw, got, tc.want)
		}
	}
	if Parse("1", now, 0) != 0 {
		t.Fatal("zero bound accepted")
	}
}
