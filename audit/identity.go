package audit

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// PrepareEvent returns an owned copy with a UUID and a microsecond-precision
// timestamp. Prepare once and retain the returned event when retrying an emission.
// Separate calls with an empty ID represent separate events.
func PrepareEvent(event *Event) (*Event, error) {
	if event == nil {
		return nil, errors.New("audit: event is required")
	}
	prepared := cloneEvent(event)
	var id uuid.UUID
	var err error
	if prepared.ID == "" {
		id, err = uuid.NewRandom()
	} else {
		id, err = parseEventID(prepared.ID)
	}
	if err != nil {
		return nil, err
	}
	prepared.ID = id.String()
	if prepared.CreatedAt.IsZero() {
		prepared.CreatedAt = time.Now()
	}
	prepared.CreatedAt = prepared.CreatedAt.UTC().Truncate(time.Microsecond)
	return prepared, nil
}

// ValidateEventID accepts an absent legacy ID or a nonzero UUID.
func ValidateEventID(id string) error {
	if id == "" {
		return nil
	}
	_, err := parseEventID(id)
	return err
}

func parseEventID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, errors.New("audit: event ID must be a nonzero UUID")
	}
	return id, nil
}
