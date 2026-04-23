package observability

import (
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Prometheus struct {
	registry        *prometheus.Registry
	requestTotal    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	inFlight        prometheus.Gauge
	authAttempts    *prometheus.CounterVec
	refreshReplay   prometheus.Counter
	dependencyDur   *prometheus.HistogramVec
}

var currentPrometheus atomic.Pointer[Prometheus]

func InitPrometheus(namespace string) (*Prometheus, error) {
	namespace = normalizeNamespace(namespace)

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	requestTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests processed by route/method/status.",
		},
		[]string{"method", "route", "status"},
	)

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency by route/method/status.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "route", "status"},
	)

	inFlight := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "in_flight_requests",
			Help:      "Current number of in-flight HTTP requests.",
		},
	)

	authAttempts := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth",
			Name:      "attempts_total",
			Help:      "Authentication attempts by flow and result.",
		},
		[]string{"flow", "result"},
	)

	refreshReplay := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "auth",
			Name:      "refresh_replay_total",
			Help:      "Detected refresh replay attempts.",
		},
	)

	dependencyDur := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "dependency",
			Name:      "duration_seconds",
			Help:      "Dependency latency by kind/operation/status.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"kind", "operation", "status"},
	)

	if err := registry.Register(requestTotal); err != nil {
		return nil, err
	}
	if err := registry.Register(requestDuration); err != nil {
		return nil, err
	}
	if err := registry.Register(inFlight); err != nil {
		return nil, err
	}
	if err := registry.Register(authAttempts); err != nil {
		return nil, err
	}
	if err := registry.Register(refreshReplay); err != nil {
		return nil, err
	}
	if err := registry.Register(dependencyDur); err != nil {
		return nil, err
	}

	prom := &Prometheus{
		registry:        registry,
		requestTotal:    requestTotal,
		requestDuration: requestDuration,
		inFlight:        inFlight,
		authAttempts:    authAttempts,
		refreshReplay:   refreshReplay,
		dependencyDur:   dependencyDur,
	}
	currentPrometheus.Store(prom)
	return prom, nil
}

func CurrentPrometheus() *Prometheus {
	return currentPrometheus.Load()
}

func ClearCurrentPrometheus() {
	currentPrometheus.Store(nil)
}

func (p *Prometheus) HTTPHandler() http.Handler {
	if p == nil || p.registry == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
	}
	return promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{})
}

func (p *Prometheus) IncInFlight() {
	if p == nil || p.inFlight == nil {
		return
	}
	p.inFlight.Inc()
}

func (p *Prometheus) DecInFlight() {
	if p == nil || p.inFlight == nil {
		return
	}
	p.inFlight.Dec()
}

func (p *Prometheus) ObserveRequest(method, route, status string, duration time.Duration) {
	if p == nil || p.requestTotal == nil || p.requestDuration == nil {
		return
	}

	method = strings.TrimSpace(method)
	route = strings.TrimSpace(route)
	status = strings.TrimSpace(status)

	if route == "" {
		route = "/"
	}
	if method == "" {
		method = "UNKNOWN"
	}
	if status == "" {
		status = "0"
	}

	p.requestTotal.WithLabelValues(method, route, status).Inc()
	p.requestDuration.WithLabelValues(method, route, status).Observe(duration.Seconds())
}

func (p *Prometheus) ObserveAuthAttempt(flow string, success bool) {
	if p == nil || p.authAttempts == nil {
		return
	}

	flow = strings.TrimSpace(flow)
	if flow == "" {
		flow = "unknown"
	}
	result := "failure"
	if success {
		result = "success"
	}

	p.authAttempts.WithLabelValues(flow, result).Inc()
}

func (p *Prometheus) IncRefreshReplay() {
	if p == nil || p.refreshReplay == nil {
		return
	}
	p.refreshReplay.Inc()
}

func (p *Prometheus) ObserveDB(operation string, duration time.Duration, err error) {
	p.observeDependency("db", operation, duration, err)
}

func (p *Prometheus) ObserveRedis(operation string, duration time.Duration, err error) {
	p.observeDependency("redis", operation, duration, err)
}

func (p *Prometheus) observeDependency(kind, operation string, duration time.Duration, err error) {
	if p == nil || p.dependencyDur == nil {
		return
	}

	kind = strings.TrimSpace(kind)
	if kind == "" {
		kind = "unknown"
	}
	operation = strings.TrimSpace(operation)
	if operation == "" {
		operation = "unknown"
	}
	status := "ok"
	if err != nil {
		status = "error"
	}

	p.dependencyDur.WithLabelValues(kind, operation, status).Observe(duration.Seconds())
}

func normalizeNamespace(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	if value == "" {
		return "controlplane"
	}
	return value
}
