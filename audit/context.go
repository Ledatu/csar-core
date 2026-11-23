package audit

import (
	"context"
	"errors"

	"github.com/ledatu/csar-core/gatewayctx"
	"go.opentelemetry.io/otel/trace"
)

// WithRequestContext returns an owned event enriched from an already trusted
// request context. It does not authenticate headers, tokens or gatewayctx values;
// callers must establish their provenance before calling it. No identity is
// inferred from Actor, transport, User-Agent or the absence of caller metadata.
// Explicit event fields, including legacy/unknown callers, take precedence.
// Call before PrepareEvent, and retain the prepared event across retries.
func WithRequestContext(ctx context.Context, event *Event) (*Event, error) {
	if ctx == nil || event == nil {
		return nil, errors.New("audit: context and event are required")
	}
	result := cloneEvent(event)
	if id, ok := gatewayctx.FromContext(ctx); ok {
		metadata := &Event{Caller: id.Caller}
		if id.Origin != nil {
			metadata.OriginCaller = id.Origin.Caller
			metadata.OperationID = id.Origin.OperationID
			metadata.ParentOperationID = id.Origin.ParentOperationID
		}
		if err := validateCallerContext(metadata); err != nil {
			return nil, err
		}
		if result.RequestID == "" {
			result.RequestID = id.RequestID
		}
		if result.Caller == nil {
			result.Caller = metadata.Caller
		}
		// Never splice another caller/operation's origin into an explicit event.
		if sameCaller(result, metadata) && (result.OperationID == "" || result.OperationID == metadata.OperationID) &&
			(result.ParentOperationID == "" || result.ParentOperationID == metadata.ParentOperationID) &&
			(result.OriginCaller == nil || metadata.OriginCaller != nil && *result.OriginCaller == *metadata.OriginCaller) {
			if result.OriginCaller == nil {
				result.OriginCaller = metadata.OriginCaller
			}
			if result.OperationID == "" {
				result.OperationID = metadata.OperationID
			}
			if result.ParentOperationID == "" {
				result.ParentOperationID = metadata.ParentOperationID
			}
		}
	}
	if span := trace.SpanContextFromContext(ctx); result.TraceID == "" && span.IsValid() {
		result.TraceID = span.TraceID().String()
	}
	if err := validateCallerContext(result); err != nil {
		return nil, err
	}
	return result, nil
}

func sameCaller(a, b *Event) bool {
	return a.Caller != nil && b.Caller != nil && *a.Caller == *b.Caller
}
