// Package fixture implements a synthetic order service used for tests and
// demos. All data is invented. A Candidate variant carries deliberate
// regressions, listed in docs/fixtures.md, so that detection can be verified
// against a known answer.
package fixture

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Variant selects which build of the service to simulate.
type Variant string

// Supported variants.
const (
	Baseline  Variant = "baseline"
	Candidate Variant = "candidate"
)

// Options configures a Service.
type Options struct {
	Variant Variant
	// Instance names this replica. It feeds noise fields so replicas of the
	// same variant disagree on them, as real replicas do.
	Instance string
	// CandidateLatency is added to /v1/reports/daily on the Candidate variant.
	CandidateLatency time.Duration
}

// Stats counts requests served by a Service.
type Stats struct {
	Requests  int64 `json:"requests"`
	Mutations int64 `json:"mutations"`
}

// Service is a stateful synthetic HTTP service.
type Service struct {
	opts      Options
	mux       *http.ServeMux
	requests  atomic.Int64
	mutations atomic.Int64

	mu    sync.Mutex
	carts map[string]int
}

// New returns a Service for the given options.
func New(opts Options) (*Service, error) {
	if opts.Variant != Baseline && opts.Variant != Candidate {
		return nil, fmt.Errorf("fixture: unknown variant %q", opts.Variant)
	}
	s := &Service{opts: opts, mux: http.NewServeMux(), carts: make(map[string]int)}
	s.routes()
	return s, nil
}

// Stats returns a snapshot of the request counters.
func (s *Service) Stats() Stats {
	return Stats{Requests: s.requests.Load(), Mutations: s.mutations.Load()}
}

// ServeHTTP implements http.Handler.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	s.mux.ServeHTTP(w, r)
}

func (s *Service) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	s.mux.HandleFunc("GET /__fixture/stats", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.Stats())
	})
	s.mux.HandleFunc("GET /v1/orders/{id}", s.getOrder)
	s.mux.HandleFunc("POST /v1/orders", s.createOrder)
	s.mux.HandleFunc("GET /v1/users/{id}", s.getUser)
	s.mux.HandleFunc("GET /v1/catalog", s.getCatalog)
	s.mux.HandleFunc("GET /v1/inventory/{sku}", s.getInventory)
	s.mux.HandleFunc("GET /v1/reports/daily", s.getDailyReport)
	s.mux.HandleFunc("GET /v1/compressed", s.getCompressed)
	s.mux.HandleFunc("GET /v1/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://forbidden.invalid/replay-must-not-follow", http.StatusFound)
	})
	s.mux.HandleFunc("POST /v1/login", s.login)
	s.mux.HandleFunc("GET /v1/me", s.getMe)
	s.mux.HandleFunc("GET /v1/cart/{sid}/step/{n}", s.cartStep)
	s.mux.HandleFunc("GET /v1/protocol", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"proto": r.Proto})
	})
}

func (s *Service) isCandidate() bool { return s.opts.Variant == Candidate }

// requestID returns a value that differs on every call and every replica.
func (s *Service) requestID() string {
	var b [8]byte
	for i := range b {
		b[i] = byte(rand.Uint32())
	}
	return s.opts.Instance + "-" + hex.EncodeToString(b[:])
}

// now returns a timestamp that differs on every call, even between replicas handling
// a request at the same instant on a clock with coarse resolution.
func now() string {
	jitter := time.Duration(rand.IntN(int(time.Millisecond)))
	return time.Now().Add(jitter).UTC().Format(time.RFC3339Nano)
}

func (s *Service) getOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !strings.HasPrefix(id, "ord-") || id == "ord-missing" {
		status := http.StatusNotFound
		if s.isCandidate() {
			// Deliberate regression: an unknown order is now a server error.
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, map[string]any{"error": "order_not_found"})
		return
	}

	customer := map[string]any{
		"id":    "cus-" + strings.TrimPrefix(id, "ord-"),
		"email": strings.TrimPrefix(id, "ord-") + "@customers.example.test",
	}
	var total any = json.Number("129.99")
	if s.isCandidate() {
		// Deliberate regression: the numeric total becomes a string.
		total = "129.99"
	} else {
		// Deliberate regression on the candidate: customer.tier disappears.
		customer["tier"] = "gold"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":            id,
		"status":        "shipped",
		"total":         total,
		"ledger_id":     json.Number("12345678901234567890"),
		"currency":      "USD",
		"customer":      customer,
		"items":         []any{map[string]any{"sku": "sku-1", "qty": 2}, map[string]any{"sku": "sku-2", "qty": 1}},
		"discount_code": nil,
		"server_time":   now(),
		"request_id":    s.requestID(),
	})
}

func (s *Service) createOrder(w http.ResponseWriter, _ *http.Request) {
	s.mutations.Add(1)
	writeJSON(w, http.StatusCreated, map[string]any{"id": "ord-new", "request_id": s.requestID()})
}

func (s *Service) getUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body := map[string]any{
		"id":           id,
		"display_name": "Synthetic User " + id,
		"server_time":  now(),
		"request_id":   s.requestID(),
	}
	if s.isCandidate() {
		// Deliberate regressions: a value change and an additive field.
		body["display_name"] = strings.ToUpper("Synthetic User " + id)
		body["loyalty_points"] = 10
	}
	writeJSON(w, http.StatusOK, body)
}

// getCatalog is the control route: no variant introduces a regression here.
func (s *Service) getCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"items":        []any{"sku-1", "sku-2", "sku-3"},
		"generated_at": now(),
		"request_id":   s.requestID(),
	})
}

// getInventory is a noisy route: stock_estimate and warehouse_hint vary on
// every replica, including the baselines. The candidate also changes their
// structure, which must stay detectable despite the noise.
func (s *Service) getInventory(w http.ResponseWriter, r *http.Request) {
	estimate := rand.IntN(1_000_000)
	body := map[string]any{
		"sku":         r.PathValue("sku"),
		"server_time": now(),
	}
	if s.isCandidate() {
		body["stock_estimate"] = strconv.Itoa(estimate)
	} else {
		body["stock_estimate"] = estimate
		body["warehouse_hint"] = "wh-" + s.opts.Instance + "-" + strconv.Itoa(rand.IntN(1_000_000))
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Service) getDailyReport(w http.ResponseWriter, r *http.Request) {
	if s.isCandidate() && s.opts.CandidateLatency > 0 {
		select {
		case <-time.After(s.opts.CandidateLatency):
		case <-r.Context().Done():
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"report": "daily", "rows": 3})
}

func (s *Service) getCompressed(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{"customer": map[string]any{"email": "gz@customers.example.test"}, "ok": true}
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	zw := gzip.NewWriter(w)
	defer func() { _ = zw.Close() }()
	_ = json.NewEncoder(zw).Encode(payload)
}

func (s *Service) login(w http.ResponseWriter, _ *http.Request) {
	s.mutations.Add(1)
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "sess-" + s.requestID(), Path: "/", HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]any{"access_token": "tok-" + s.requestID()})
}

func (s *Service) getMe(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": "synthetic"})
}

// cartStep enforces that a session's steps arrive in order on this replica,
// which makes replay ordering violations observable as 409 responses.
func (s *Service) cartStep(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_step"})
		return
	}
	s.mu.Lock()
	expected := s.carts[sid] + 1
	if n == expected {
		s.carts[sid] = n
	}
	s.mu.Unlock()
	if n != expected {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "out_of_order", "expected": expected})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sid": sid, "step": n})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
