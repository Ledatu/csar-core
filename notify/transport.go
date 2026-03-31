package notify

import "context"

// Transport delivers notifications to a remote ingest endpoint.
type Transport interface {
	Send(ctx context.Context, notifications []*Notification) error
	Close() error
}
