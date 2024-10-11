package fixture

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type deployment struct {
	a, b, candidate *httptest.Server
	aSvc            *Service
}

func deploy(t *testing.T) deployment {
	t.Helper()
	start := func(o Options) (*httptest.Server, *Service) {
		svc, err := New(o)
		if err != nil {
			t.Fatalf("New(%+v): %v", o, err)
		}
		srv := httptest.NewServer(svc)
		t.Cleanup(srv.Close)
		return srv, svc
	}
	a, aSvc := start(Options{Variant: Baseline, Instance: "a"})
	b, _ := start(Options{Variant: Baseline, Instance: "b"})
	c, _ := start(Options{Variant: Candidate, Instance: "c", CandidateLatency: 40 * time.Millisecond})
	return deployment{a: a, b: b, candidate: c, aSvc: aSvc}
}

// response is the part of an HTTP response these tests inspect. The body is
// read and closed by do.
type response struct {
	StatusCode int
	Header     http.Header
}

func do(t *testing.T, method, url string, body string, header map[string]string) (response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{StatusCode: resp.StatusCode, Header: resp.Header}, data
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, data := do(t, http.MethodGet, url, "", nil)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode %s: %v: %s", url, err, data)
	}
	return resp.StatusCode, out
}

func without(m map[string]any, keys ...string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	for _, k := range keys {
		delete(out, k)
	}
	return out
}

func TestNewRejectsUnknownVariant(t *testing.T) {
	if _, err := New(Options{Variant: "other", Instance: "x"}); err == nil {
		t.Fatal("want error for unknown variant")
	}
}

func TestBaselinesAgreeExceptOnDeclaredNoiseFields(t *testing.T) {
	d := deploy(t)
	for path, noise := range map[string][]string{
		"/v1/orders/ord-1":   {"server_time", "request_id"},
		"/v1/users/usr-1":    {"server_time", "request_id"},
		"/v1/catalog":        {"generated_at", "request_id"},
		"/v1/inventory/sku1": {"stock_estimate", "warehouse_hint", "server_time"},
	} {
		statusA, a := getJSON(t, d.a.URL+path)
		statusB, b := getJSON(t, d.b.URL+path)
		if statusA != statusB {
			t.Errorf("%s: status %d vs %d", path, statusA, statusB)
		}
		for _, field := range noise {
			if reflect.DeepEqual(a[field], b[field]) && field != "generated_at" && field != "server_time" {
				t.Errorf("%s: noise field %s is identical (%v) on both baselines", path, field, a[field])
			}
			if _, ok := a[field]; !ok {
				t.Errorf("%s: noise field %s missing", path, field)
			}
		}
		if !reflect.DeepEqual(without(a, noise...), without(b, noise...)) {
			t.Errorf("%s: baselines differ outside noise fields:\nA=%v\nB=%v", path, a, b)
		}
	}
}

func TestOrderPreservesLargeNumberLiteral(t *testing.T) {
	d := deploy(t)
	_, data := do(t, http.MethodGet, d.a.URL+"/v1/orders/ord-1", "", nil)
	if !strings.Contains(string(data), `"ledger_id":12345678901234567890`) {
		t.Fatalf("ledger_id literal not preserved: %s", data)
	}
}

func TestCandidateRegressions(t *testing.T) {
	d := deploy(t)

	t.Run("field removed", func(t *testing.T) {
		_, base := getJSON(t, d.a.URL+"/v1/orders/ord-1")
		_, cand := getJSON(t, d.candidate.URL+"/v1/orders/ord-1")
		if _, ok := base["customer"].(map[string]any)["tier"]; !ok {
			t.Fatal("baseline lost customer.tier")
		}
		if _, ok := cand["customer"].(map[string]any)["tier"]; ok {
			t.Fatal("candidate still has customer.tier")
		}
	})

	t.Run("type changed", func(t *testing.T) {
		_, base := getJSON(t, d.a.URL+"/v1/orders/ord-1")
		_, cand := getJSON(t, d.candidate.URL+"/v1/orders/ord-1")
		if _, ok := base["total"].(json.Number); !ok {
			t.Fatalf("baseline total = %T", base["total"])
		}
		if _, ok := cand["total"].(string); !ok {
			t.Fatalf("candidate total = %T", cand["total"])
		}
	})

	t.Run("status class changed", func(t *testing.T) {
		baseStatus, _ := getJSON(t, d.a.URL+"/v1/orders/ord-missing")
		candStatus, _ := getJSON(t, d.candidate.URL+"/v1/orders/ord-missing")
		if baseStatus != http.StatusNotFound || candStatus != http.StatusInternalServerError {
			t.Fatalf("status baseline=%d candidate=%d", baseStatus, candStatus)
		}
	})

	t.Run("value changed and field added", func(t *testing.T) {
		_, base := getJSON(t, d.a.URL+"/v1/users/usr-1")
		_, cand := getJSON(t, d.candidate.URL+"/v1/users/usr-1")
		if base["display_name"] == cand["display_name"] {
			t.Fatalf("display_name unchanged: %v", base["display_name"])
		}
		if _, ok := base["loyalty_points"]; ok {
			t.Fatal("baseline must not have loyalty_points")
		}
		if _, ok := cand["loyalty_points"]; !ok {
			t.Fatal("candidate must add loyalty_points")
		}
	})

	t.Run("structural regressions on noisy route", func(t *testing.T) {
		_, base := getJSON(t, d.a.URL+"/v1/inventory/sku1")
		_, cand := getJSON(t, d.candidate.URL+"/v1/inventory/sku1")
		if _, ok := base["stock_estimate"].(json.Number); !ok {
			t.Fatalf("baseline stock_estimate = %T", base["stock_estimate"])
		}
		if _, ok := cand["stock_estimate"].(string); !ok {
			t.Fatalf("candidate stock_estimate = %T", cand["stock_estimate"])
		}
		if _, ok := cand["warehouse_hint"]; ok {
			t.Fatal("candidate must drop warehouse_hint")
		}
	})

	t.Run("latency added", func(t *testing.T) {
		start := time.Now()
		do(t, http.MethodGet, d.candidate.URL+"/v1/reports/daily", "", nil)
		if got := time.Since(start); got < 40*time.Millisecond {
			t.Fatalf("candidate latency = %v, want >= 40ms", got)
		}
	})

	t.Run("control route has no regression", func(t *testing.T) {
		_, base := getJSON(t, d.a.URL+"/v1/catalog")
		_, cand := getJSON(t, d.candidate.URL+"/v1/catalog")
		if !reflect.DeepEqual(without(base, "generated_at", "request_id"), without(cand, "generated_at", "request_id")) {
			t.Fatalf("catalog differs:\n%v\n%v", base, cand)
		}
	})
}

func TestInstancesHaveIndependentState(t *testing.T) {
	d := deploy(t)
	for step := 1; step <= 2; step++ {
		status, _ := getJSON(t, d.a.URL+"/v1/cart/s1/step/"+strconv.Itoa(step))
		if status != http.StatusOK {
			t.Fatalf("A step %d: status %d", step, status)
		}
	}
	status, _ := getJSON(t, d.b.URL+"/v1/cart/s1/step/1")
	if status != http.StatusOK {
		t.Fatalf("B must start from its own state, got %d", status)
	}
}

func TestCartRejectsOutOfOrderSteps(t *testing.T) {
	d := deploy(t)
	status, body := getJSON(t, d.a.URL+"/v1/cart/s2/step/2")
	if status != http.StatusConflict {
		t.Fatalf("status = %d, body = %v", status, body)
	}
}

func TestMutatingCallsAreCounted(t *testing.T) {
	d := deploy(t)
	resp, _ := do(t, http.MethodPost, d.a.URL+"/v1/orders", `{"sku":"sku1"}`, map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := d.aSvc.Stats().Mutations; got != 1 {
		t.Fatalf("Mutations = %d, want 1", got)
	}
}

func TestLoginIssuesCookieAndToken(t *testing.T) {
	d := deploy(t)
	resp, data := do(t, http.MethodPost, d.a.URL+"/v1/login", `{"username":"u1","password":"p1"}`, map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Set-Cookie") == "" {
		t.Fatal("missing Set-Cookie")
	}
	if !strings.Contains(string(data), "access_token") {
		t.Fatalf("body = %s", data)
	}
}

func TestMeRequiresCredentialAndNeverEchoesIt(t *testing.T) {
	d := deploy(t)
	resp, _ := do(t, http.MethodGet, d.a.URL+"/v1/me", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status without credential = %d", resp.StatusCode)
	}
	resp, data := do(t, http.MethodGet, d.a.URL+"/v1/me", "", map[string]string{"Authorization": "Bearer synthetic-credential"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status with credential = %d", resp.StatusCode)
	}
	if strings.Contains(string(data), "synthetic-credential") {
		t.Fatalf("credential echoed: %s", data)
	}
}

func TestCompressedRouteServesGzipWhenAccepted(t *testing.T) {
	d := deploy(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, d.a.URL+"/v1/compressed", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q", resp.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("not JSON: %s", data)
	}
}

func TestRedirectRoutePointsOffOrigin(t *testing.T) {
	d := deploy(t)
	resp, _ := do(t, http.MethodGet, d.a.URL+"/v1/redirect", "", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "http://forbidden.invalid/") {
		t.Fatalf("Location = %q", resp.Header.Get("Location"))
	}
}

func TestProtocolRouteReportsWhatItSaw(t *testing.T) {
	d := deploy(t)
	_, body := getJSON(t, d.a.URL+"/v1/protocol")
	if body["proto"] != "HTTP/1.1" {
		t.Fatalf("body = %v", body)
	}
}
