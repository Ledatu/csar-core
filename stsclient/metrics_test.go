package stsclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/httpx/clientmetrics"
	"github.com/ledatu/csar-core/httpx/clientx"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsConstructorKeepsAuthRetryAndTimeout(t *testing.T) {
	var exchanges, calls atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"synthetic-token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer issuer.Close()
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Csar-Authorization") != "Bearer synthetic-token" {
			t.Error("auth header changed")
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer router.Close()
	cfg := redirectConfig(t, issuer.URL, router.URL)
	cfg.RouterTimeout = 3 * time.Second
	reg := prometheus.NewRegistry()
	metrics, err := clientmetrics.New(reg)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := NewRouterClientWithMetrics(&cfg, nil, metrics)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Client.Timeout != cfg.RouterTimeout || rc.BaseURL != router.URL {
		t.Fatal("client settings changed")
	}
	req, err := http.NewRequestWithContext(context.Background(), "GET", router.URL+"/read", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, callErr := clientx.DoJSON[map[string]bool](context.Background(), req, clientx.Options{Client: rc.Client})
	if callErr != nil || !out["ok"] {
		t.Fatalf("request failed: %v", callErr)
	}
	if exchanges.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("existing STS caching/retry behavior changed: exchanges=%d calls=%d", exchanges.Load(), calls.Load())
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]uint64{}
	for _, family := range families {
		if family.GetName() != "csar_client_request_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "scope" {
					counts[label.GetValue()] += metric.Histogram.GetSampleCount()
				}
			}
		}
	}
	if counts["router"] != 1 || counts["sts"] != 1 {
		t.Fatalf("wrong logical observations: %v", counts)
	}
}
