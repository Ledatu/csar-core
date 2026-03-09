package grpcjwt

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type subjectKey struct{}

// UnaryInterceptor returns a gRPC unary interceptor that validates JWT tokens
// from the "authorization" metadata field. On success, the extracted subject
// is stored in the context and can be retrieved via SubjectFromContext.
//
// If no authorization metadata is present, the request passes through
// (the subject may come from the request field instead).
func (v *Validator) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}

		authValues := md.Get("authorization")
		if len(authValues) == 0 {
			return handler(ctx, req)
		}

		token := authValues[0]
		token = strings.TrimPrefix(token, "Bearer ")

		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "empty token")
		}

		subject, err := v.ValidateToken(token)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		ctx = context.WithValue(ctx, subjectKey{}, subject)
		return handler(ctx, req)
	}
}

// SubjectFromContext retrieves the JWT-extracted subject from the context.
func SubjectFromContext(ctx context.Context) (string, bool) {
	sub, ok := ctx.Value(subjectKey{}).(string)
	return sub, ok
}
