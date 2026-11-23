package audit

import (
	"context"
	"testing"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"go.opentelemetry.io/otel/trace"
)

func requestAuditContext() context.Context {
	id := &caller.Identity{Version: caller.Version, CallerKind: caller.Service, CallerID: "svc:reports", EffectiveSubject: "svc:reports", CredentialKind: caller.STS, Assurance: caller.Verified}
	origin := &caller.Identity{Version: caller.Version, CallerKind: caller.Agent, CallerID: "agent:1", OwnerSubject: "user:1", EffectiveSubject: "user:1", CredentialKind: caller.APIKey, CredentialID: "key:1", Assurance: caller.Verified}
	ctx := gatewayctx.NewContext(context.Background(), &gatewayctx.Identity{Caller: id, RequestID: "request:1", Origin: &gatewayctx.Origin{
		Caller: origin, OperationID: "operation:1", ParentOperationID: "parent:1", ExpiresAt: time.Now().Add(time.Minute),
	}})
	return trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2},
	}))
}

func TestWithRequestContextCopiesTrustedMetadata(t *testing.T) {
	input := &Event{Actor: "legacy-actor", Metadata: []byte(`{"retained":true}`)}
	ctx := requestAuditContext()
	event, err := WithRequestContext(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if event.Actor != input.Actor || event.RequestID != "request:1" || event.Caller.CallerID != "svc:reports" || event.OriginCaller.CallerID != "agent:1" ||
		event.OperationID != "operation:1" || event.ParentOperationID != "parent:1" || event.TraceID != "01000000000000000000000000000000" || event.ID != "" || !event.CreatedAt.IsZero() {
		t.Fatal("missing metadata or invented emission identity", event)
	}
	event.Caller.CallerID = "changed"
	event.OriginCaller.CallerID = "changed"
	event.Metadata[0] = ' '
	again, err := WithRequestContext(ctx, input)
	if err != nil || again.Caller.CallerID != "svc:reports" || again.OriginCaller.CallerID != "agent:1" || string(input.Metadata) != `{"retained":true}` || input.Caller != nil {
		t.Fatal("context or event aliased")
	}
}

func TestWithRequestContextPreservesExplicitAndLegacyFields(t *testing.T) {
	unknown := &caller.Identity{Version: caller.Version, CallerKind: caller.Unknown, EffectiveSubject: "user:old", CredentialKind: caller.APIKey, Assurance: caller.Legacy}
	input := &Event{Actor: "legacy", Caller: unknown, RequestID: "explicit-request", TraceID: "explicit-trace", OperationID: "explicit-operation", ParentOperationID: "explicit-parent"}
	event, err := WithRequestContext(requestAuditContext(), input)
	if err != nil {
		t.Fatal(err)
	}
	if *event.Caller != *unknown || event.Actor != input.Actor || event.RequestID != input.RequestID || event.TraceID != input.TraceID || event.OperationID != input.OperationID || event.ParentOperationID != input.ParentOperationID || event.OriginCaller != nil {
		t.Fatal("explicit fields overwritten or mixed with another operation")
	}
	ctxID, _ := gatewayctx.FromContext(requestAuditContext())
	event, err = WithRequestContext(requestAuditContext(), &Event{Caller: ctxID.Caller, OperationID: "another-operation"})
	if err != nil || event.OriginCaller != nil || event.ParentOperationID != "" {
		t.Fatal("another operation's origin was attached")
	}
}

func TestWithRequestContextDoesNotInventIdentity(t *testing.T) {
	event, err := WithRequestContext(context.Background(), &Event{Actor: "agent-looking-label"})
	if err != nil || event.Caller != nil || event.OriginCaller != nil || event.TraceID != "" || event.OperationID != "" {
		t.Fatal("identity inferred without verified context")
	}
	ctx := gatewayctx.NewContext(context.Background(), &gatewayctx.Identity{Caller: &caller.Identity{Version: 999}})
	if _, err := WithRequestContext(ctx, &Event{}); err == nil {
		t.Fatal("invalid supplied caller silently discarded")
	}
	if _, err := WithRequestContext(context.Background(), &Event{Caller: &caller.Identity{Version: 999}}); err == nil {
		t.Fatal("invalid explicit caller silently discarded")
	}
	if _, err := WithRequestContext(context.Background(), nil); err == nil {
		t.Fatal("nil event accepted")
	}
}
