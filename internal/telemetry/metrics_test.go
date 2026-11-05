package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Bispulm/replaydiff/internal/capture"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

func get(t *testing.T, handler http.Handler, path string) (int, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return recorder.Code, string(body)
}

func testMetrics() *CaptureMetrics {
	return NewCaptureMetrics(CaptureMetricsConfig{
		Stats: func() capture.Stats {
			return capture.Stats{
				Observed:              10,
				Persisted:             7,
				Dropped:               map[string]int64{"queue_full": 2},
				BodiesOmitted:         map[string]int64{"malformed_json": 1},
				SyncFailures:          1,
				QueueDepth:            3,
				MemoryBudgetUsedBytes: 4096,
			}
		},
		QueueCapacity:     1024,
		MemoryBudgetBytes: 256 << 20,
	})
}

// Counters come from the same statistics capture prints when it stops, read at scrape
// time, so the two can't disagree.
func TestCaptureMetricsReflectCaptureStatistics(t *testing.T) {
	metrics := testMetrics()
	metrics.ObserveExchange(traffic.ProtocolHTTP2, 25*time.Millisecond)
	code, body := get(t, AdminHandler(metrics.Gatherer(), func() bool { return true }), "/metrics")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for _, line := range []string{
		"replaydiff_capture_exchanges_total 10",
		"replaydiff_capture_records_persisted_total 7",
		`replaydiff_capture_records_dropped_total{reason="queue_full"} 2`,
		`replaydiff_capture_bodies_omitted_total{reason="malformed_json"} 1`,
		"replaydiff_capture_storage_sync_failures_total 1",
		"replaydiff_capture_queue_depth 3",
		"replaydiff_capture_queue_capacity 1024",
		"replaydiff_capture_memory_budget_used_bytes 4096",
		"replaydiff_capture_memory_budget_bytes 2.68435456e+08",
		`replaydiff_capture_exchange_duration_seconds_count{protocol="h2"} 1`,
	} {
		if !strings.Contains(body, line+"\n") {
			t.Errorf("missing %q", line)
		}
	}
}

// Every drop reason is exported from the start, at zero, so a rate or an alert works
// before the first drop rather than only after it.
func TestEveryDropReasonStartsAtZero(t *testing.T) {
	_, body := get(t, AdminHandler(testMetrics().Gatherer(), func() bool { return true }), "/metrics")
	for _, reason := range capture.DropReasons() {
		if reason == capture.DropQueueFull {
			continue
		}
		if line := `replaydiff_capture_records_dropped_total{reason="` + string(reason) + `"} 0`; !strings.Contains(body, line+"\n") {
			t.Errorf("missing %q", line)
		}
	}
}

func TestMetricsFollowPrometheusConventions(t *testing.T) {
	problems, err := testutil.GatherAndLint(testMetrics().Gatherer())
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range problems {
		t.Errorf("%s: %s", problem.Metric, problem.Text)
	}
}

func TestHealthEndpoints(t *testing.T) {
	ready := false
	handler := AdminHandler(testMetrics().Gatherer(), func() bool { return ready })
	if code, _ := get(t, handler, "/livez"); code != http.StatusOK {
		t.Fatalf("livez %d", code)
	}
	if code, _ := get(t, handler, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before ready: %d", code)
	}
	ready = true
	if code, _ := get(t, handler, "/readyz"); code != http.StatusOK {
		t.Fatalf("readyz when ready: %d", code)
	}
	if code, _ := get(t, handler, "/other"); code != http.StatusNotFound {
		t.Fatalf("unknown path: %d", code)
	}
}
