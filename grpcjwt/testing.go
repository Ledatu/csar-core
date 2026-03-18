package grpcjwt

import "context"

// TestContextWithSubject injects a subject into the context using the same
// key as the JWT interceptor. Intended for use in tests only.
func TestContextWithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectKey{}, subject)
}
