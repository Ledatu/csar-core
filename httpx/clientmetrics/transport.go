package clientmetrics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

type transport struct {
	base    http.RoundTripper
	metrics *Metrics
	scope   string
}

// WrapClient returns a shallow client copy with observation outside its existing
// transport stack. Redirect policy, timeout, jar, transport and pooling survive.
// A nil metrics pointer is a no-op; a nil client selects http.DefaultClient.
// Rewrapping an owned observer replaces it rather than double-counting it.
func WrapClient(client *http.Client, m *Metrics, scope Scope) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	if m == nil {
		return client
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	for {
		old, ok := base.(*transport)
		if !ok {
			break
		}
		if old.metrics == m && old.scope == scopeLabel(scope) {
			return client
		}
		base = old.base
	}
	copyClient := *client
	copyClient.Transport = &transport{base: base, metrics: m, scope: scopeLabel(scope)}
	return &copyClient
}

func source(client *http.Client) (*Metrics, string) {
	if client == nil {
		client = http.DefaultClient
	}
	t, ok := client.Transport.(*transport)
	if !ok {
		return nil, ""
	}
	return t.metrics, t.scope
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	method := methodLabel(req.Method)
	headerTime := time.Since(start)
	if err != nil {
		result := "transport_error"
		switch {
		case errors.Is(err, context.Canceled):
			result = "canceled"
		case errors.Is(err, context.DeadlineExceeded):
			result = "deadline"
		}
		t.metrics.headerDuration.WithLabelValues(t.scope, method, "none", result).Observe(headerTime.Seconds())
		t.metrics.requestDuration.WithLabelValues(t.scope, method, "none", result).Observe(headerTime.Seconds())
		return resp, err
	}
	if resp == nil {
		return nil, nil
	} // Preserve the client's existing invalid-response error.
	headerResult := "ok"
	if resp.StatusCode >= 400 {
		headerResult = "http_error"
	}
	t.metrics.headerDuration.WithLabelValues(t.scope, method, statusLabel(resp.StatusCode), headerResult).Observe(headerTime.Seconds())
	wire, decoded := representation(resp)
	if resp.Body == nil || resp.Body == http.NoBody {
		t.metrics.recordBody(t.scope, method, resp.StatusCode, start, time.Now(), 0, 0, "eof", wire, decoded)
		return resp, nil
	}
	body := &observedBody{base: resp.Body, metrics: t.metrics, scope: t.scope, method: method, status: resp.StatusCode, start: start, wireKnown: wire, decodedKnown: decoded}
	if rw, ok := resp.Body.(io.ReadWriteCloser); ok {
		resp.Body = &observedReadWriteBody{observedBody: body, writer: rw}
	} else {
		resp.Body = body
	}
	return resp, nil
}

// CloseIdleConnections keeps http.Client.CloseIdleConnections effective.
func (t *transport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// CancelRequest retains compatibility with transports that still use this hook.
func (t *transport) CancelRequest(req *http.Request) {
	if canceler, ok := t.base.(interface{ CancelRequest(*http.Request) }); ok {
		canceler.CancelRequest(req)
	}
}

type observedReadWriteBody struct {
	*observedBody
	writer io.Writer
}

func (b *observedReadWriteBody) Write(p []byte) (int, error) { return b.writer.Write(p) }

type observedBody struct {
	base                    io.ReadCloser
	metrics                 *Metrics
	scope, method           string
	status                  int
	start                   time.Time
	wireKnown, decodedKnown bool
	mu                      sync.Mutex
	reads                   int
	bytes                   int64
	readTime                time.Duration
	completion              string
	end                     time.Time
	reported                bool
	closed                  bool
}

type bodyReport struct {
	end        time.Time
	readTime   time.Duration
	bytes      int64
	completion string
}

// finishLocked reports only after Close and outstanding Reads finish. This
// includes a caller drain after a failed/oversized read without blocking Close.
// Duration still ends at the first terminal Read, excluding later caller work.
func (b *observedBody) finishLocked() *bodyReport {
	if b.reported || !b.closed || b.completion == "" || b.reads != 0 {
		return nil
	}
	b.reported = true
	return &bodyReport{end: b.end, readTime: b.readTime, bytes: b.bytes, completion: b.completion}
}
func (b *observedBody) report(r *bodyReport) {
	if r != nil {
		b.metrics.recordBody(b.scope, b.method, b.status, b.start, r.end, r.readTime, r.bytes, r.completion, b.wireKnown, b.decodedKnown)
	}
}
func (b *observedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	b.reads++
	b.mu.Unlock()
	start := time.Now()
	n, err := b.base.Read(p)
	end := time.Now()
	b.mu.Lock()
	b.reads--
	b.bytes += int64(n)
	b.readTime += end.Sub(start)
	if err != nil && b.completion == "" {
		b.completion = "read_error"
		// io.Reader/io.ReadAll treat only the exact EOF sentinel as normal
		// completion; a wrapped EOF remains an application read failure.
		if err == io.EOF {
			b.completion = "eof"
		}
		b.end = end
	}
	r := b.finishLocked()
	b.mu.Unlock()
	b.report(r)
	return n, err
}
func (b *observedBody) Close() error {
	err := b.base.Close()
	end := time.Now()
	b.mu.Lock()
	b.closed = true
	if b.completion == "" {
		b.completion = "early_close"
		b.end = end
	}
	r := b.finishLocked()
	b.mu.Unlock()
	b.report(r)
	return err
}
