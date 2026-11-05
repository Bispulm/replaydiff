package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// startUpstream serves the same JSON body of about bodySize bytes to every request. It
// does as little as possible, so that its own cost is small and constant.
func startUpstream(bodySize int) (string, func(), error) {
	var b strings.Builder
	b.WriteString(`{"id":"ord-1","items":[`)
	for i := 0; b.Len() < bodySize-2; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"sku":"sku-`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`","card":"4242424242424242"}`)
	}
	b.WriteString("]}")
	body := []byte(b.String())
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	return "http://" + listener.Addr().String(), func() { _ = server.Close() }, nil
}

// Phase is the outcome of one period of open-loop load.
type Phase struct {
	Target   string  `json:"target"`
	Offered  float64 `json:"offered_per_second"`
	Achieved float64 `json:"achieved_per_second"`
	Sent     int     `json:"sent"`
	Errors   int     `json:"errors"`
	P50      float64 `json:"p50_ms"`
	P90      float64 `json:"p90_ms"`
	P99      float64 `json:"p99_ms"`
	Max      float64 `json:"max_ms"`
}

// openLoop sends requests at a fixed rate for the duration, using at most conns
// connections at once. Latency runs from when a request was due, not from when a
// connection became free, so a slow server shows as latency rather than lowering the
// load it receives.
func openLoop(ctx context.Context, url string, rate float64, duration time.Duration, conns int) Phase {
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: conns, MaxConnsPerHost: conns}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	total := max(1, int(rate*duration.Seconds()))
	interval := time.Duration(float64(time.Second) / rate)
	start := time.Now().Add(50 * time.Millisecond)
	due := make(chan time.Time, total)
	for i := range total {
		due <- start.Add(time.Duration(i) * interval)
	}
	close(due)

	latencies := make([]time.Duration, 0, total)
	errors := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range conns {
		wg.Go(func() {
			for at := range due {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(time.Until(at))
				ok := get(ctx, client, url)
				took := time.Since(at)
				mu.Lock()
				if ok {
					latencies = append(latencies, took)
				} else {
					errors++
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)
	phase := Phase{Offered: rate, Sent: total, Errors: errors, Achieved: float64(len(latencies)) / elapsed.Seconds()}
	if len(latencies) > 0 {
		slices.Sort(latencies)
		phase.P50, phase.P90, phase.P99 = ms(percentile(latencies, 50)), ms(percentile(latencies, 90)), ms(percentile(latencies, 99))
		phase.Max = ms(latencies[len(latencies)-1])
	}
	return phase
}

func get(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/v1/orders/ord-1", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return err == nil && resp.StatusCode == http.StatusOK
}

// percentile is the nearest-rank percentile of sorted values.
func percentile(sorted []time.Duration, p float64) time.Duration {
	rank := int(float64(len(sorted))*p/100+0.999999) - 1
	return sorted[min(max(rank, 0), len(sorted)-1)]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
