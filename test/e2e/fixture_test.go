package e2e

import (
	"net/http"
	"strings"
	"testing"
)

func TestFixtureProcessesRunIndependently(t *testing.T) {
	a := start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--variant", "baseline", "--instance", "a")
	b := start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--variant", "baseline", "--instance", "b")
	c := start(t, nil, "replaydiff-fixture", "--listen", "127.0.0.1:0", "--variant", "candidate", "--instance", "c")

	aURL, bURL, cURL := a.baseURL(t), b.baseURL(t), c.baseURL(t)

	if status, _ := httpGet(t, aURL+"/v1/cart/s1/step/1", nil); status != http.StatusOK {
		t.Fatalf("A step 1: status %d", status)
	}
	if status, _ := httpGet(t, bURL+"/v1/cart/s1/step/1", nil); status != http.StatusOK {
		t.Fatalf("B must keep its own cart state, got status %d", status)
	}

	if status, _ := httpGet(t, aURL+"/v1/orders/ord-missing", nil); status != http.StatusNotFound {
		t.Fatalf("baseline missing order: status %d", status)
	}
	if status, _ := httpGet(t, cURL+"/v1/orders/ord-missing", nil); status != http.StatusInternalServerError {
		t.Fatalf("candidate missing order: status %d", status)
	}

	// Stopping one fixture must not disturb the others.
	if err := a.stop(t); err != nil {
		t.Fatalf("stop A: %v", err)
	}
	if status, body := httpGet(t, bURL+"/healthz", nil); status != http.StatusOK || !strings.Contains(body, "ok") {
		t.Fatalf("B after stopping A: status %d, body %q", status, body)
	}
}
