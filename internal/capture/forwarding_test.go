package capture

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bispulm/replaydiff/internal/traffic"
)

func TestForwardsRequestAndResponseUnchanged(t *testing.T) {
	var seenBody, seenQuery, seenHeader, seenMethod, seenHost string
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody, seenQuery, seenHeader, seenMethod, seenHost = string(body), r.URL.RawQuery, r.Header.Get("X-Custom"), r.Method, r.Host
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Reply", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":   true}`)
	}))
	got := h.send(http.MethodPost, "/a/b?x=1&y=2", []byte(`{"n":  1}`), map[string]string{"X-Custom": "v", "Content-Type": "application/json"})

	if got.status != http.StatusCreated || got.header.Get("X-Reply") != "yes" {
		t.Fatalf("reply = %+v", got)
	}
	// The client sees the upstream's exact bytes. Re-encoding is only for storage.
	if string(got.body) != `{"ok":   true}` {
		t.Fatalf("body = %q", got.body)
	}
	if seenBody != `{"n":  1}` || seenQuery != "x=1&y=2" || seenHeader != "v" || seenMethod != http.MethodPost {
		t.Fatalf("upstream saw body=%q query=%q header=%q method=%q", seenBody, seenQuery, seenHeader, seenMethod)
	}
	if !strings.Contains(h.proxy.URL, seenHost) {
		t.Fatalf("Host = %q, want the client's host %q preserved", seenHost, h.proxy.URL)
	}
}

func TestHopByHopHeadersAreNotForwarded(t *testing.T) {
	var keepAlive, connScoped, connection string
	h := newHarness(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		keepAlive, connScoped, connection = r.Header.Get("Keep-Alive"), r.Header.Get("X-Conn-Scoped"), r.Header.Get("Connection")
	}))
	h.send(http.MethodGet, "/", nil, map[string]string{"Connection": "X-Conn-Scoped", "X-Conn-Scoped": "1", "Keep-Alive": "timeout=5"})
	if keepAlive != "" || connScoped != "" || connection != "" {
		t.Fatalf("hop-by-hop reached upstream: keep-alive=%q scoped=%q connection=%q", keepAlive, connScoped, connection)
	}
}

func TestContentLengthIsPreserved(t *testing.T) {
	var seen int64
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.ContentLength
		w.Header().Set("Content-Length", "5")
		_, _ = io.WriteString(w, "hello")
	}))
	got := h.send(http.MethodPost, "/", []byte("0123456789"), nil)
	if seen != 10 {
		t.Fatalf("upstream Content-Length = %d", seen)
	}
	if got.header.Get("Content-Length") != "5" {
		t.Fatalf("client Content-Length = %q", got.header.Get("Content-Length"))
	}
}

func TestResponseTrailersAreForwardedAndRecorded(t *testing.T) {
	secret := sentinel(t)
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Checksum, Set-Cookie")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
		w.Header().Set("X-Checksum", "abc")
		w.Header().Set("Set-Cookie", "sid="+secret)
	}))
	got := h.send(http.MethodGet, "/", nil, nil)
	if got.trailer.Get("X-Checksum") != "abc" {
		t.Fatalf("client trailer = %v", got.trailer)
	}
	if !strings.Contains(got.trailer.Get("Set-Cookie"), secret) {
		t.Fatalf("live traffic must keep its real trailer: %v", got.trailer)
	}

	rec := h.onlyRecord()
	if !hasString(rec.Response.Trailers["X-Checksum"], "abc") {
		t.Fatalf("recorded trailers = %v", rec.Response.Trailers)
	}
	h.assertNoSecret(secret)
}

func TestRequestTrailersAreRecordedRedacted(t *testing.T) {
	secret := sentinel(t)
	h := newHarness(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.proxy.URL+"/", io.NopCloser(strings.NewReader(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	req.Trailer = http.Header{"Authorization": {"Bearer " + secret}, "X-Check": {"ok"}}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	rec := h.onlyRecord()
	if !hasString(rec.Request.Trailers["X-Check"], "ok") {
		t.Fatalf("trailers = %v", rec.Request.Trailers)
	}
	h.assertNoSecret(secret)
}

func TestStreamingResponseIsNotBuffered(t *testing.T) {
	release := make(chan struct{})
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"first":`)
		http.NewResponseController(w).Flush() //nolint:errcheck // httptest writers support Flush.
		<-release
		_, _ = io.WriteString(w, `1}`)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.proxy.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	first := make([]byte, 9)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatalf("first chunk must arrive while upstream is still writing: %v", err)
	}
	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(first)+string(rest) != `{"first":1}` {
		t.Fatalf("body = %s%s", first, rest)
	}
	if rec := h.onlyRecord(); rec.Response.Body.State != traffic.BodyPresent {
		t.Fatalf("record = %+v", rec.Response.Body)
	}
}

func TestUpstreamConnectionFailureGivesClientNormalError(t *testing.T) {
	secret := sentinel(t)
	h := newHarness(t, http.NotFoundHandler())
	h.upstream.Close()

	got := h.send(http.MethodGet, "/x?token="+secret, nil, map[string]string{"X-Probe": "1"})
	if got.status != http.StatusBadGateway {
		t.Fatalf("status = %d", got.status)
	}
	if bytes.Contains(got.body, []byte(secret)) {
		t.Fatalf("error body quotes the request: %s", got.body)
	}

	rec := h.onlyRecord()
	if rec.Outcome.Transport != traffic.TransportUpstreamError || rec.Response != nil {
		t.Fatalf("record = %+v", rec)
	}
	h.assertNoSecret(secret)
}

func TestUpstreamAbortMidBodyIsVisibleToClientAndRecorded(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"partial":`)
		http.NewResponseController(w).Flush() //nolint:errcheck // httptest writers support Flush.
		panic(http.ErrAbortHandler)
	}))
	got := h.send(http.MethodGet, "/", nil, nil)
	if got.readErr == nil {
		t.Fatalf("client must see the broken response, got clean body %q", got.body)
	}
	rec := h.onlyRecord()
	if rec.Outcome.Transport != traffic.TransportUpstreamAbort {
		t.Fatalf("outcome = %s", rec.Outcome.Transport)
	}
	if rec.Response.Body.State != traffic.BodyTruncated || rec.Response.Body.Data != nil {
		t.Fatalf("body = %+v", rec.Response.Body)
	}
}

func TestClientCancellationReachesUpstreamAndIsRecorded(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	started := make(chan struct{})
	h := newHarness(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(upstreamCanceled)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.proxy.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		errc <- err
	}()
	<-started
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("client err = %v", err)
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation didn't reach upstream")
	}
	if rec := h.onlyRecord(); rec.Outcome.Transport != traffic.TransportClientCanceled {
		t.Fatalf("outcome = %s", rec.Outcome.Transport)
	}
}

func TestEarlyUpstreamResponseDoesNotHangOrRace(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	got := h.send(http.MethodPost, "/", bytes.Repeat([]byte("x"), 4<<20), map[string]string{"Content-Type": "application/json"})
	if got.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", got.status)
	}
	rec := h.onlyRecord()
	if rec.Replay.Eligible {
		t.Fatalf("a request not seen in full can't be replayable: %+v", rec.Replay)
	}
}

func TestProtocolSwitchPassesThroughUnrecorded(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = rw.Flush()
		line, _ := rw.ReadString('\n')
		_, _ = rw.WriteString(line)
		_ = rw.Flush()
	}))
	var dialer net.Dialer
	conn, err := dialer.DialContext(context.Background(), "tcp", strings.TrimPrefix(h.proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
	_ = conn.Close()
	waitFor(t, "unsupported protocol count", func() bool {
		return h.capture.Stats().Dropped[string(DropUnsupportedProtocol)] == 1
	})
}

func TestAbsoluteFormRequestCannotNameADestination(t *testing.T) {
	var seenPath string
	h := newHarness(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seenPath = r.URL.Path }))
	var dialer net.Dialer
	conn, err := dialer.DialContext(context.Background(), "tcp", strings.TrimPrefix(h.proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET http://evil.example.test/x?y=1 HTTP/1.1\r\nHost: evil.example.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatal(err)
	}
	if seenPath != "/x" {
		t.Fatalf("upstream path = %q", seenPath)
	}
	rec := h.onlyRecord()
	if rec.Request.Path != "/x" || rec.Request.RawQuery != "y=1" {
		t.Fatalf("request = %+v", rec.Request)
	}
	h.assertNoSecret("evil.example.test")
}

func TestConcurrentTrafficIsAllRecorded(t *testing.T) {
	h := newHarness(t, jsonHandler(`{"ok":true}`))
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := range 200 {
		wg.Go(func() {
			got := h.send(http.MethodPost, fmt.Sprintf("/r/%d", i), []byte(`{"n":1}`), map[string]string{"Content-Type": "application/json"})
			if got.status != http.StatusOK {
				failures.Add(1)
			}
		})
	}
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d requests failed", n)
	}
	records := h.records()
	if len(records) != 200 {
		t.Fatalf("records = %d, stats = %+v", len(records), h.capture.Stats())
	}
	seen := make(map[uint64]bool)
	for _, rec := range records {
		if seen[rec.Seq] {
			t.Fatalf("duplicate seq %d", rec.Seq)
		}
		seen[rec.Seq] = true
	}
}

func TestSequenceFollowsArrivalNotCompletion(t *testing.T) {
	releaseFirst := make(chan struct{})
	firstStarted := make(chan struct{})
	h := newHarness(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			close(firstStarted)
			<-releaseFirst
		}
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.send(http.MethodGet, "/first", nil, nil)
	}()
	<-firstStarted
	h.send(http.MethodGet, "/second", nil, nil)
	close(releaseFirst)
	<-done

	records := h.records()
	if len(records) != 2 || records[0].Request.Path != "/first" || records[1].Request.Path != "/second" {
		t.Fatalf("records = %v, want arrival order", paths(records))
	}
}

func paths(records []*traffic.Record) []string {
	out := make([]string, 0, len(records))
	for _, rec := range records {
		out = append(out, rec.Request.Path)
	}
	return out
}

// Trailers follow a complete body. After an abort the response is in an unknown state,
// and the transport may still own its trailer map.
func TestAbortedResponseRecordsNoTrailers(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"partial":`)
		http.NewResponseController(w).Flush() //nolint:errcheck // httptest writers support Flush.
		w.Header().Set("X-Checksum", "abc")
		panic(http.ErrAbortHandler)
	}))
	if got := h.send(http.MethodGet, "/", nil, nil); got.readErr == nil {
		t.Fatal("client must see the broken response")
	}
	rec := h.onlyRecord()
	if rec.Outcome.Transport != traffic.TransportUpstreamAbort || len(rec.Response.Trailers) != 0 {
		t.Fatalf("record = %+v", rec.Response)
	}
}
