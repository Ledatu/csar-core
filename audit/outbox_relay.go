package audit

import (
	"context"
	"log/slog"
	"sync"

	"github.com/ledatu/csar-core/stsclient"
	"github.com/prometheus/client_golang/prometheus"
)

// StartRouterRelay owns the router transport and stops/joins the worker before
// the producer closes its DB. Call the returned stop even on startup failure.
func (o *PGOutbox) StartRouterRelay(ctx context.Context, cfg *stsclient.ServiceAuthConfig, logger *slog.Logger, registry prometheus.Registerer) (func(), error) {
	transport, err := NewRouterTransport(cfg, logger)
	if err != nil {
		return nil, err
	}
	collector := newOutboxCollector(o)
	if registry != nil {
		if err := registry.Register(collector); err != nil {
			_ = transport.Close()
			return nil, err
		}
	}
	relayCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); o.Run(relayCtx, transport, logger) }()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
			_ = transport.Close()
			if registry != nil {
				registry.Unregister(collector)
			}
		})
	}, nil
}

type outboxCollector struct {
	o                   *PGOutbox
	count, age, success *prometheus.Desc
}

func newOutboxCollector(o *PGOutbox) *outboxCollector {
	labels := prometheus.Labels{"service": o.service}
	return &outboxCollector{o: o,
		count:   prometheus.NewDesc("audit_outbox_pending_events", "Committed audit events awaiting a confirmed receipt", nil, labels),
		age:     prometheus.NewDesc("audit_outbox_oldest_age_seconds", "Age of oldest pending event, including leased/retrying rows", nil, labels),
		success: prometheus.NewDesc("audit_outbox_scrape_success", "Whether the last outbox backlog query succeeded", nil, labels)}
}
func (c *outboxCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.count
	ch <- c.age
	ch <- c.success
}
func (c *outboxCollector) Collect(ch chan<- prometheus.Metric) {
	b, err := c.o.Backlog(context.Background())
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.success, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.success, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.count, prometheus.GaugeValue, float64(b.Count))
	ch <- prometheus.MustNewConstMetric(c.age, prometheus.GaugeValue, b.OldestAge.Seconds())
}
