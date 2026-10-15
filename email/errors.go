package email

import "fmt"

// Outcome indicates whether another attempt could duplicate an accepted send.
type Outcome string

const (
	Retryable Outcome = "retryable"
	Rejected  Outcome = "rejected"
	Unknown   Outcome = "unknown"
)

// SendError contains safe diagnostics only; SMTP replies may echo secrets or
// message content and must never be included in errors that services log.
type SendError struct {
	Stage   string
	Outcome Outcome
	Code    int
}

func (e *SendError) Error() string {
	return fmt.Sprintf("email submission failed: stage=%s outcome=%s code=%d", e.Stage, e.Outcome, e.Code)
}

func failure(stage string, outcome Outcome, code int) *SendError {
	return &SendError{Stage: stage, Outcome: outcome, Code: code}
}
