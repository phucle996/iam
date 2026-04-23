package observability

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const traceparentHeader = "traceparent"

type OTel struct {
	tracer     trace.Tracer
	propagator propagation.TextMapPropagator
	shutdown   func(context.Context) error
}

func InitOTel(_ context.Context, serviceName string) (*OTel, error) {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		serviceName = "controlplane"
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"",
			attribute.String("service.name", serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("observability: init otel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(1.0))),
		sdktrace.WithResource(res),
	)

	propagator := propagation.TraceContext{}
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagator)

	return &OTel{
		tracer:     tp.Tracer(serviceName),
		propagator: propagator,
		shutdown:   tp.Shutdown,
	}, nil
}

func (o *OTel) Shutdown(ctx context.Context) error {
	if o == nil || o.shutdown == nil {
		return nil
	}
	return o.shutdown(ctx)
}

func (o *OTel) Extract(ctx context.Context, headers http.Header) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if o == nil || o.propagator == nil {
		return ctx
	}
	if headers == nil {
		return ctx
	}
	return o.propagator.Extract(ctx, propagation.HeaderCarrier(headers))
}

func (o *OTel) Inject(ctx context.Context, headers http.Header) {
	if ctx == nil || headers == nil {
		return
	}
	if o == nil || o.propagator == nil {
		return
	}
	o.propagator.Inject(ctx, propagation.HeaderCarrier(headers))
}

func (o *OTel) StartServerSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	if o == nil || o.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return o.tracer.Start(ctx, strings.TrimSpace(name), trace.WithSpanKind(trace.SpanKindServer))
}

func ExtractTraceparent(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(traceparentHeader))
}
