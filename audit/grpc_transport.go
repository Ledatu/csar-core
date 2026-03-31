package audit

import (
	"context"

	auditv1 "github.com/ledatu/csar-proto/csar/audit/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GRPCTransport sends batches via AuditIngestService.RecordEvents.
// The caller owns the gRPC connection lifecycle, TLS, and dial options.
type GRPCTransport struct {
	client auditv1.AuditIngestServiceClient
}

// NewGRPCTransport wraps a connected gRPC client.
func NewGRPCTransport(conn grpc.ClientConnInterface) *GRPCTransport {
	if conn == nil {
		return &GRPCTransport{}
	}
	return &GRPCTransport{
		client: auditv1.NewAuditIngestServiceClient(conn),
	}
}

// Send implements Transport.
func (t *GRPCTransport) Send(ctx context.Context, events []*Event) error {
	if t == nil || t.client == nil || len(events) == 0 {
		return nil
	}
	req := &auditv1.RecordEventsRequest{
		Events: eventsToProto(events),
	}
	_, err := t.client.RecordEvents(ctx, req)
	return err
}

// Close implements Transport. The underlying connection is not closed.
func (*GRPCTransport) Close() error {
	return nil
}

func eventsToProto(events []*Event) []*auditv1.AuditEvent {
	out := make([]*auditv1.AuditEvent, 0, len(events))
	for _, e := range events {
		if e == nil {
			continue
		}
		out = append(out, eventToProto(e))
	}
	return out
}

func eventToProto(e *Event) *auditv1.AuditEvent {
	msg := &auditv1.AuditEvent{
		Service:     e.Service,
		Actor:       e.Actor,
		Action:      e.Action,
		TargetType:  e.TargetType,
		TargetId:    e.TargetID,
		ScopeType:   e.ScopeType,
		ScopeId:     e.ScopeID,
		BeforeState: append([]byte(nil), e.BeforeState...),
		AfterState:  append([]byte(nil), e.AfterState...),
		Metadata:    append([]byte(nil), e.Metadata...),
		RequestId:   e.RequestID,
		ClientIp:    e.ClientIP,
	}
	if !e.CreatedAt.IsZero() {
		msg.Timestamp = timestamppb.New(e.CreatedAt)
	}
	return msg
}
