package audit

import "context"

// Recorder is the minimal contract needed by mutation handlers that emit
// audit events but do not query them.
type Recorder interface {
	Record(ctx context.Context, event *Event) error
}

// ClientRecorder adapts the async audit client to the Recorder interface.
// It never returns delivery errors to callers; async failures are handled by
// the underlying client fallback behavior.
type ClientRecorder struct {
	client  *Client
	service string
}

// NewClientRecorder wraps an async Client for handler-friendly Record calls.
func NewClientRecorder(client *Client, service string) Recorder {
	if client == nil {
		return nil
	}
	return &ClientRecorder{client: client, service: service}
}

// Record implements Recorder.
func (r *ClientRecorder) Record(ctx context.Context, event *Event) error {
	if r == nil || r.client == nil || event == nil {
		return nil
	}

	ev := cloneEvent(event)
	if ev.Service == "" {
		ev.Service = r.service
	}
	r.client.Record(ctx, ev)
	return nil
}
