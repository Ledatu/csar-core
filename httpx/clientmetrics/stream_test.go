package clientmetrics_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/httpx/clientmetrics"
	"github.com/ledatu/csar-core/httpx/jsonstream"
	"github.com/prometheus/client_golang/prometheus"
)

type streamFixture struct {
	Rows []int `json:"rows"`
}

type streamFailure struct{}

func (streamFailure) Read([]byte) (int, error) { return 0, errors.New("fixture read failed") }

func TestElementStreamingMetricsAreNotBufferedMetrics(t *testing.T) {
	for _, tc := range []struct {
		result string
		body   io.Reader
		limit  int64
	}{
		{"ok", strings.NewReader(`{"rows":[1,2]}`), 100},
		{"decode_error", strings.NewReader(`{"rows":[1,`), 100},
		{"too_large", strings.NewReader(`{"rows":[1,2]}`), 5},
		{"read_error", streamFailure{}, 100},
	} {
		t.Run(tc.result, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			m, err := clientmetrics.New(reg)
			if err != nil {
				t.Fatal(err)
			}
			client := clientmetrics.WrapClient(nil, m, clientmetrics.ScopeRouter)
			_, info, _ := clientmetrics.DecodeObject(client, tc.body, tc.limit, func(out *streamFixture) []jsonstream.Field {
				return []jsonstream.Field{jsonstream.Array("rows", &out.Rows)}
			})
			// Use the reader's actual consumption as the metric contract. It
			// includes failed/sentinel reads and is not an accepted-body size.
			families, err := reg.Gather()
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			for _, f := range families {
				if f.GetName() == "csar_client_json_buffer_bytes" || f.GetName() == "csar_client_json_duration_seconds" {
					t.Fatal("stream was reported as buffered work")
				}
				if f.GetName() != "csar_client_json_stream_bytes" && f.GetName() != "csar_client_json_stream_duration_seconds" {
					continue
				}
				seen++
				if len(f.Metric) != 1 || f.Metric[0].GetHistogram().GetSampleCount() != 1 {
					t.Fatal("stream observation count changed")
				}
				metric := f.Metric[0]
				labels := map[string]string{}
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				if len(labels) != 2 || labels["scope"] != "router" || labels["result"] != tc.result {
					t.Fatalf("unexpected labels: %v", labels)
				}
				if f.GetName() == "csar_client_json_stream_bytes" && metric.GetHistogram().GetSampleSum() != float64(info.BytesRead) {
					t.Fatal("stream bytes mismatch")
				}
			}
			if seen != 2 {
				t.Fatalf("stream metrics families=%d", seen)
			}
		})
	}
}
