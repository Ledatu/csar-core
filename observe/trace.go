// Package observe provides one-call bootstrap for OpenTelemetry tracing
// and Prometheus metrics. Services use this to get consistent observability
// without duplicating setup boilerplate.
package observe

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

// TraceConfig controls the OpenTelemetry tracing pipeline.
type TraceConfig struct {
	ServiceName    string  // service identity reported to the backend
	ServiceVersion string  // version tag
	Endpoint       string  // OTLP gRPC endpoint (e.g. "localhost:4317"); empty = noop
	SampleRate     float64 // 0.0–1.0; 0 defaults to 1.0
	Insecure       bool    // disable TLS for the OTLP connection
}

// TracerProvider wraps the SDK provider with a shutdown helper.
type TracerProvider struct {
	tp *sdktrace.TracerProvider
}

// InitTracer creates and registers a global TracerProvider.
// When Endpoint is empty a noop provider is returned.
func InitTracer(ctx context.Context, cfg TraceConfig) (*TracerProvider, error) {
	if cfg.SampleRate == 0 {
		cfg.SampleRate = 1.0
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
			semconv.ServiceVersionKey.String(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("observe: creating resource: %w", err)
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))),
	}

	if cfg.Endpoint != "" {
		exporterOpts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			exporterOpts = append(exporterOpts, otlptracegrpc.WithInsecure())
		}
		exp, err := otlptracegrpc.New(ctx, exporterOpts...)
		if err != nil {
			return nil, fmt.Errorf("observe: creating OTLP exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exp))
	}

	tp := sdktrace.NewTracerProvider(opts...)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &TracerProvider{tp: tp}, nil
}

// Shutdown flushes pending spans and shuts down the provider.
func (p *TracerProvider) Shutdown(ctx context.Context) error {
	if p == nil || p.tp == nil {
		return nil
	}
	return p.tp.Shutdown(ctx)
}

// Close is a convenience that shuts down with a 5-second timeout.
func (p *TracerProvider) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.Shutdown(ctx)
}

// Noop returns a TracerProvider backed by a noop exporter.
func Noop() *TracerProvider {
	tp := sdktrace.NewTracerProvider()
	return &TracerProvider{tp: tp}
}
