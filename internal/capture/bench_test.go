package capture

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// BenchmarkRequest compares a request sent straight to a server with the same request
// through capture, which also records it. The difference is capture's cost per request
// on this machine, including the background work it causes.
func BenchmarkRequest(b *testing.B) {
	body := bytes.Repeat([]byte(`{"k":"v"},`), 100)
	h := newHarness(b, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4}}
	get := func(b *testing.B, url string) {
		req, err := http.NewRequestWithContext(b.Context(), http.MethodGet, url+"/v1/orders/ord-1", nil)
		if err != nil {
			b.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	for _, target := range []struct{ name, url string }{{"direct", h.upstream.URL}, {"captured", h.proxy.URL}} {
		b.Run(target.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				get(b, target.url)
			}
		})
	}
}
