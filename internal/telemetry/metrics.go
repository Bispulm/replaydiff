// Package telemetry exposes capture's metrics and health, and sets up tracing. Nothing it
// exports carries traffic content: metric labels and span attributes are drawn from
// constants in the code, such as reasons and protocols, never from requests.
package telemetry

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Bispulm/replaydiff/internal/capture"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// CaptureMetricsConfig describes the capture process being measured.
type CaptureMetricsConfig struct {
	// Stats is read at every scrape.
	Stats             func() capture.Stats
	QueueCapacity     int
	MemoryBudgetBytes int64
}

// CaptureMetrics holds capture's metrics in a registry of its own.
type CaptureMetrics struct {
	registry *prometheus.Registry
	duration *prometheus.HistogramVec
}

// NewCaptureMetrics registers capture's metrics, with Go runtime and process metrics.
func NewCaptureMetrics(cfg CaptureMetricsConfig) *CaptureMetrics {
	m := &CaptureMetrics{
		registry: prometheus.NewRegistry(),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "replaydiff_capture_exchange_duration_seconds",
			Help: "Time from a request arriving at the proxy to its response finishing, upstream time included.",
			// From a fast local call to a slow upstream, roughly doubling.
			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"protocol"}),
	}
	m.registry.MustRegister(
		m.duration,
		&captureCollector{cfg: cfg},
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// ObserveExchange records one finished exchange. Its signature matches capture.Config's
// OnExchange.
func (m *CaptureMetrics) ObserveExchange(protocol traffic.Protocol, d time.Duration) {
	m.duration.WithLabelValues(string(protocol)).Observe(d.Seconds())
}

// Gatherer returns the registry, for serving.
func (m *CaptureMetrics) Gatherer() prometheus.Gatherer { return m.registry }

var (
	exchangesDesc = prometheus.NewDesc("replaydiff_capture_exchanges_total",
		"Exchanges the proxy saw.", nil, nil)
	persistedDesc = prometheus.NewDesc("replaydiff_capture_records_persisted_total",
		"Records written to storage.", nil, nil)
	droppedDesc = prometheus.NewDesc("replaydiff_capture_records_dropped_total",
		"Recordings dropped, by reason. Live traffic was forwarded regardless.", []string{"reason"}, nil)
	omittedDesc = prometheus.NewDesc("replaydiff_capture_bodies_omitted_total",
		"Bodies observed but not stored, by reason.", []string{"reason"}, nil)
	syncFailuresDesc = prometheus.NewDesc("replaydiff_capture_storage_sync_failures_total",
		"Failed attempts to flush storage to disk.", nil, nil)
	queueDepthDesc = prometheus.NewDesc("replaydiff_capture_queue_depth",
		"Finished exchanges waiting to be recorded.", nil, nil)
	queueCapacityDesc = prometheus.NewDesc("replaydiff_capture_queue_capacity",
		"Exchanges the queue holds before recordings are dropped.", nil, nil)
	budgetUsedDesc = prometheus.NewDesc("replaydiff_capture_memory_budget_used_bytes",
		"Body bytes held across in-flight and queued exchanges.", nil, nil)
	budgetDesc = prometheus.NewDesc("replaydiff_capture_memory_budget_bytes",
		"Body bytes that can be held before bodies are omitted.", nil, nil)
)

// captureCollector turns a capture.Stats snapshot into metrics at scrape time.
type captureCollector struct {
	cfg CaptureMetricsConfig
}

func (c *captureCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{exchangesDesc, persistedDesc, droppedDesc, omittedDesc, syncFailuresDesc, queueDepthDesc, queueCapacityDesc, budgetUsedDesc, budgetDesc} {
		ch <- d
	}
}

func (c *captureCollector) Collect(ch chan<- prometheus.Metric) {
	stats := c.cfg.Stats()
	counter := func(d *prometheus.Desc, v int64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v), labels...)
	}
	gauge := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v)
	}
	counter(exchangesDesc, stats.Observed)
	counter(persistedDesc, stats.Persisted)
	for _, reason := range capture.DropReasons() {
		counter(droppedDesc, stats.Dropped[string(reason)], string(reason))
	}
	for reason, n := range stats.BodiesOmitted {
		counter(omittedDesc, n, reason)
	}
	counter(syncFailuresDesc, stats.SyncFailures)
	gauge(queueDepthDesc, float64(stats.QueueDepth))
	gauge(queueCapacityDesc, float64(c.cfg.QueueCapacity))
	gauge(budgetUsedDesc, float64(stats.MemoryBudgetUsedBytes))
	gauge(budgetDesc, float64(c.cfg.MemoryBudgetBytes))
}

// AdminHandler serves /metrics, /livez and /readyz. It belongs on its own listener,
// apart from the proxy, so that probes and scrapes are never recorded.
func AdminHandler(gatherer prometheus.Gatherer, ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}
