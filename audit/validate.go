package audit

import (
	"encoding/json"
	"fmt"
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
	return nil
}
