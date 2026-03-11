package observe

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// HTTPMiddleware returns an HTTP middleware that creates a span for
// each request using the given TracerProvider and operation name.
func HTTPMiddleware(tp trace.TracerProvider, operation string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, operation,
			otelhttp.WithTracerProvider(tp),
		)
	}
}
