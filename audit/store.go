// Package audit provides audit event persistence for admin mutations.
// It lives in csar-core so that any service (authn, authz, etc.) can
// record and query audit events without duplicating code.
package audit

import (
	"context"
	"encoding/json"
	"time"
)

// Event represents a single admin audit log entry.
type Event struct {
	ID          string          `json:"id"`
	Service     string          `json:"service,omitempty"`
	Actor       string          `json:"actor"`
	Action      string          `json:"action"`
	TargetType  string          `json:"target_type"`
	TargetID    string          `json:"target_id"`
	ScopeType   string          `json:"scope_type"`
	ScopeID     string          `json:"scope_id"`
	BeforeState json.RawMessage `json:"before_state,omitempty"`
	AfterState  json.RawMessage `json:"after_state,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	RequestID   string          `json:"request_id,omitempty"`
	ClientIP    string          `json:"client_ip,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ListFilter specifies query parameters for listing audit events.
type ListFilter struct {
	ScopeType  string
	ScopeID    string
	Service    string
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	RequestID  string
	Since      *time.Time
	Until      *time.Time
	Cursor     string
	Limit      int
}

// ListResult holds a page of audit events with an optional next cursor.
type ListResult struct {
	Events     []Event `json:"events"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

// Store defines the persistence contract for audit events.
type Store interface {
	Record(ctx context.Context, event *Event) error
	List(ctx context.Context, filter *ListFilter) (*ListResult, error)
}
