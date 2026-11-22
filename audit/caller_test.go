package audit

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/ledatu/csar-core/caller"
)

func TestLegacyLocalStoreRejectsCallerContextBeforeWriting(t *testing.T) {
	for _, event := range []*Event{
		{Caller: &caller.Identity{}}, {OriginCaller: &caller.Identity{}},
		{OperationID: "op:1"}, {ParentOperationID: "op:0"}, {TraceID: "trace:1"},
	} {
		st := &PostgresStore{}
		if err := st.Record(context.Background(), event); !errors.Is(err, ErrCallerContextUnsupported) {
			t.Fatal("legacy local sink silently discarded caller context", err)
		}
	}
}

func callerEvent(t *testing.T) *Event {
	t.Helper()
	event, err := PrepareEvent(&Event{Actor: "legacy-actor", Action: "report.read", TargetType: "report", ScopeType: "tenant",
		Caller: &caller.Identity{Version: caller.Version, CallerKind: caller.Service, CallerID: "svc:reporting",
			EffectiveSubject: "svc:reporting", CredentialKind: caller.STS, Assurance: caller.Verified},
		OriginCaller: &caller.Identity{Version: caller.Version, CallerKind: caller.Agent, CallerID: "agent:1", OwnerSubject: "user:1",
			EffectiveSubject: "user:1", CredentialKind: caller.APIKey, CredentialID: "key:1", Assurance: caller.Verified},
		OperationID: "operation:1", ParentOperationID: "operation:0", TraceID: "trace:1"})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestCallerContextOwnsMemoryAndSurvivesBindings(t *testing.T) {
	original := callerEvent(t)
	prepared, err := PrepareEvent(original)
	if err != nil {
		t.Fatal(err)
	}
	original.Caller.CallerID, original.OriginCaller.CallerID = "changed", "changed"
	if prepared.Caller.CallerID != "svc:reporting" || prepared.OriginCaller.CallerID != "agent:1" {
		t.Fatal("prepared event aliases caller memory")
	}
	decoded, err := EventFromProto(EventToProto(prepared))
	if err != nil || !reflect.DeepEqual(prepared, decoded) {
		t.Fatalf("caller context lost in protobuf: %v", err)
	}
	body, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	var replay Event
	if err := json.Unmarshal(body, &replay); err != nil || !reflect.DeepEqual(prepared, &replay) {
		t.Fatalf("caller context lost in JSON: %v", err)
	}
	if prepared.Actor != "legacy-actor" {
		t.Fatal("new caller context replaced the historical actor")
	}
}

func TestRejectInvalidCallerContext(t *testing.T) {
	for name, mutate := range map[string]func(*Event){
		"version": func(e *Event) { e.Caller.Version = 2 },
		"kind":    func(e *Event) { e.OriginCaller.CallerKind = "robot" },
		"origin":  func(e *Event) { e.Caller = nil },
		"control": func(e *Event) { e.OperationID = "op\nsecret" },
	} {
		t.Run(name, func(t *testing.T) {
			event := callerEvent(t)
			mutate(event)
			if _, err := PrepareEvent(event); err == nil {
				t.Fatal("malformed caller context accepted by producer")
			}
			if _, err := EventFromProto(EventToProto(event)); err == nil {
				t.Fatal("malformed caller context accepted by ingest")
			}
		})
	}
}

func TestLegacyEventJSONBytesUnchanged(t *testing.T) {
	const legacy = `{"id":"c30ca535-d731-4559-9238-d2b6906f1129","service":"owner","actor":"user","action":"read","target_type":"seller","target_id":"1","scope_type":"tenant","scope_id":"1","request_id":"r1","created_at":"2026-11-21T00:00:00Z"}`
	var event Event
	if err := json.Unmarshal([]byte(legacy), &event); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(&event)
	if err != nil || string(body) != legacy {
		t.Fatalf("legacy bytes changed: %v %s", err, body)
	}
}
