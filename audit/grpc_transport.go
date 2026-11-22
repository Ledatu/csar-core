package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/ledatu/csar-core/caller"
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
		Events: EventsToProto(events),
	}
	_, err := t.client.RecordEvents(ctx, req)
	return err
}

// Close implements Transport. The underlying connection is not closed.
func (*GRPCTransport) Close() error {
	return nil
}

// GRPCSingleTransport sends each event individually via RecordEvent.
type GRPCSingleTransport struct {
	client auditv1.AuditIngestServiceClient
}

func NewGRPCSingleTransport(conn grpc.ClientConnInterface) *GRPCSingleTransport {
	if conn == nil {
		return &GRPCSingleTransport{}
	}
	return &GRPCSingleTransport{
		client: auditv1.NewAuditIngestServiceClient(conn),
	}
}

func (t *GRPCSingleTransport) Send(ctx context.Context, events []*Event) error {
	if t == nil || t.client == nil || len(events) == 0 {
		return nil
	}
	var firstErr error
	for _, e := range events {
		if e == nil {
			continue
		}
		_, err := t.client.RecordEvent(ctx, &auditv1.RecordEventRequest{
			Event: EventToProto(e),
		})
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (*GRPCSingleTransport) Close() error {
	return nil
}

// EventsToProto converts a slice of audit events to their protobuf representation.
func EventsToProto(events []*Event) []*auditv1.AuditEvent {
	out := make([]*auditv1.AuditEvent, 0, len(events))
	for _, e := range events {
		if e == nil {
			continue
		}
		out = append(out, EventToProto(e))
	}
	return out
}

// EventToProto converts a single audit event to its protobuf representation.
func EventToProto(e *Event) *auditv1.AuditEvent {
	msg := &auditv1.AuditEvent{
		Id:                e.ID,
		Service:           e.Service,
		Actor:             e.Actor,
		Action:            e.Action,
		TargetType:        e.TargetType,
		TargetId:          e.TargetID,
		ScopeType:         e.ScopeType,
		ScopeId:           e.ScopeID,
		BeforeState:       append([]byte(nil), e.BeforeState...),
		AfterState:        append([]byte(nil), e.AfterState...),
		Metadata:          append([]byte(nil), e.Metadata...),
		RequestId:         e.RequestID,
		ClientIp:          e.ClientIP,
		Caller:            callerToProto(e.Caller),
		OriginCaller:      callerToProto(e.OriginCaller),
		OperationId:       e.OperationID,
		ParentOperationId: e.ParentOperationID,
		TraceId:           e.TraceID,
	}
	if !e.CreatedAt.IsZero() {
		msg.Timestamp = timestamppb.New(e.CreatedAt)
	}
	return msg
}

// EventFromProto is the shared ingest binding. It validates structure, not the
// producer's authority; ingress must authenticate and authorize the producer.
func EventFromProto(pb *auditv1.AuditEvent) (*Event, error) {
	if pb == nil {
		return nil, fmt.Errorf("audit: event is required")
	}
	event := &Event{ID: pb.Id, Service: pb.Service, Actor: pb.Actor, Action: pb.Action,
		TargetType: pb.TargetType, TargetID: pb.TargetId, ScopeType: pb.ScopeType, ScopeID: pb.ScopeId,
		BeforeState: append([]byte(nil), pb.BeforeState...), AfterState: append([]byte(nil), pb.AfterState...),
		Metadata: append([]byte(nil), pb.Metadata...), RequestID: pb.RequestId, ClientIP: pb.ClientIp,
		Caller: callerFromProto(pb.Caller), OriginCaller: callerFromProto(pb.OriginCaller),
		OperationID: pb.OperationId, ParentOperationID: pb.ParentOperationId, TraceID: pb.TraceId}
	if pb.Timestamp != nil {
		if err := pb.Timestamp.CheckValid(); err != nil {
			return nil, fmt.Errorf("audit: invalid timestamp")
		}
		event.CreatedAt = pb.Timestamp.AsTime()
	} else {
		event.CreatedAt = time.Now().UTC()
	}
	if err := ValidateEvent(event); err != nil {
		return nil, err
	}
	return event, nil
}

func callerToProto(id *caller.Identity) *auditv1.CallerIdentity {
	if id == nil {
		return nil
	}
	return &auditv1.CallerIdentity{Version: uint32(id.Version), CallerKind: string(id.CallerKind), CallerId: id.CallerID,
		OwnerSubject: id.OwnerSubject, EffectiveSubject: id.EffectiveSubject, CredentialKind: string(id.CredentialKind),
		CredentialId: id.CredentialID, ClientId: id.ClientID, ConnectionId: id.ConnectionID, Assurance: string(id.Assurance)}
}

func callerFromProto(id *auditv1.CallerIdentity) *caller.Identity {
	if id == nil {
		return nil
	}
	return &caller.Identity{Version: int(id.Version), CallerKind: caller.Kind(id.CallerKind), CallerID: id.CallerId,
		OwnerSubject: id.OwnerSubject, EffectiveSubject: id.EffectiveSubject, CredentialKind: caller.CredentialKind(id.CredentialKind),
		CredentialID: id.CredentialId, ClientID: id.ClientId, ConnectionID: id.ConnectionId, Assurance: caller.Assurance(id.Assurance)}
}
