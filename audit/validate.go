package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxStateBytes    = 64 << 10
	MaxMetadataBytes = 16 << 10
)

// ValidateEvent is the wire contract shared by ingest and transactional producers.
// An absent ID is accepted for legacy input; PrepareEvent supplies it before storage.
func ValidateEvent(e *Event) error {
	if e == nil {
		return fmt.Errorf("nil event")
	}
	if err := ValidateEventID(e.ID); err != nil {
		return err
	}
	if e.Actor == "" || e.Action == "" || e.TargetType == "" || e.ScopeType == "" {
		return fmt.Errorf("actor, action, target_type and scope_type are required")
	}
	for _, raw := range []json.RawMessage{e.BeforeState, e.AfterState, e.Metadata} {
		if len(raw) > 0 && !json.Valid(raw) {
			return fmt.Errorf("event JSON fields must contain valid JSON")
		}
	}
	if len(e.BeforeState) > MaxStateBytes || len(e.AfterState) > MaxStateBytes {
		return fmt.Errorf("audit state exceeds %d bytes", MaxStateBytes)
	}
	if len(e.Metadata) > MaxMetadataBytes {
		return fmt.Errorf("audit metadata exceeds %d bytes", MaxMetadataBytes)
	}
	return validateCallerContext(e)
}

func validateCallerContext(e *Event) error {
	if e.Caller != nil {
		if err := e.Caller.Validate(); err != nil {
			return fmt.Errorf("audit caller: %w", err)
		}
	}
	if e.OriginCaller != nil {
		if e.Caller == nil {
			return fmt.Errorf("audit: origin requires an immediate caller")
		}
		if err := e.OriginCaller.Validate(); err != nil {
			return fmt.Errorf("audit origin: %w", err)
		}
	}
	for _, field := range []struct{ name, value string }{
		{"operation_id", e.OperationID}, {"parent_operation_id", e.ParentOperationID}, {"trace_id", e.TraceID},
	} {
		if len(field.value) > 128 || !utf8.ValidString(field.value) || strings.IndexFunc(field.value, func(r rune) bool {
			return unicode.IsControl(r) || unicode.IsSpace(r)
		}) >= 0 {
			return fmt.Errorf("audit: invalid %s", field.name)
		}
	}
	return nil
}
