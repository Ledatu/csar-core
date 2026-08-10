// Package errors provides domain error types shared across all CSAR ecosystem services.
// Errors carry a machine-readable code, a human-readable message, and an HTTP status
// mapping so that transport layers can produce consistent structured responses.
package errors

import "fmt"

// Code is a machine-readable error classification.
type Code string

const (
	CodeValidation   Code = "VALIDATION_ERROR"
	CodeNotFound     Code = "NOT_FOUND"
	CodeConflict     Code = "CONFLICT"
	CodeInternal     Code = "INTERNAL"
	CodeUnavailable  Code = "UNAVAILABLE"
	CodeRateLimited  Code = "RATE_LIMITED"
	CodeForbidden    Code = "FORBIDDEN"
	CodeUnauthorized Code = "UNAUTHORIZED"
)

// Error is the standard domain error used throughout the CSAR ecosystem.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
	Cause   error  `json:"-"`
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Cause }

// Is supports errors.Is matching by code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// --- Constructors ---

// NotFound creates a 404 NOT_FOUND error.
func NotFound(format string, args ...any) *Error {
	return &Error{Code: CodeNotFound, Message: fmt.Sprintf(format, args...), Status: 404}
}

// Validation creates a 400 VALIDATION_ERROR.
func Validation(format string, args ...any) *Error {
	return &Error{Code: CodeValidation, Message: fmt.Sprintf(format, args...), Status: 400}
}

// Conflict creates a 409 CONFLICT error.
func Conflict(format string, args ...any) *Error {
	return &Error{Code: CodeConflict, Message: fmt.Sprintf(format, args...), Status: 409}
}

// Internal wraps an underlying error as a 500 INTERNAL error.
// The cause is never serialized to clients.
func Internal(cause error) *Error {
	return &Error{Code: CodeInternal, Message: "internal error", Status: 500, Cause: cause}
}

// Internalf creates a 500 INTERNAL error with a formatted message.
func Internalf(format string, args ...any) *Error {
	return &Error{Code: CodeInternal, Message: fmt.Sprintf(format, args...), Status: 500}
}

// Unavailable creates a 503 UNAVAILABLE error.
func Unavailable(format string, args ...any) *Error {
	return &Error{Code: CodeUnavailable, Message: fmt.Sprintf(format, args...), Status: 503}
}

// RateLimited creates a 429 RATE_LIMITED error.
func RateLimited(format string, args ...any) *Error {
	return &Error{Code: CodeRateLimited, Message: fmt.Sprintf(format, args...), Status: 429}
}

// Forbidden creates a 403 FORBIDDEN error.
func Forbidden(format string, args ...any) *Error {
	return &Error{Code: CodeForbidden, Message: fmt.Sprintf(format, args...), Status: 403}
}

// Unauthorized creates a 401 UNAUTHORIZED error.
func Unauthorized(format string, args ...any) *Error {
	return &Error{Code: CodeUnauthorized, Message: fmt.Sprintf(format, args...), Status: 401}
}

// Wrap attaches a cause to an existing domain error, returning a copy.
func Wrap(err *Error, cause error) *Error {
	cp := *err
	cp.Cause = cause
	return &cp
}
