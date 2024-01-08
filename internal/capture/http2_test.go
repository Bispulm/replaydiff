package capture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// wire says how one hop of the path is carried.
type wire string

const (
	wireHTTP1 wire = "http1"
	wireH2C   wire = "h2c"
	wireTLSH2 wire = "tls-h2"
)

func protocolsFor(w wire) *http.Protocols {
	p := new(http.Protocols)
	switch w {
	case wireHTTP1:
		p.SetHTTP1(true)
	case wireH2C:
		p.SetUnencryptedHTTP2(true)
	case wireTLSH2:
		p.SetHTTP2(true)
	}
	return p
}

// startOn runs handler as a real server that speaks only the given protocol, so
// a fallback to HTTP/1.1 fails rather than passing by accident.
func startOn(t *testing.T, w wire, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	if w == wireTLSH2 {
		server.EnableHTTP2 = true
		server.StartTLS()
	} else {
		server.Config.Protocols = protocolsFor(w)
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func clientFor(w wire, server *httptest.Server) *http.Transport {
	transport := &http.Transport{Protocols: protocolsFor(w), DisableCompression: true}
	if w == wireTLSH2 {
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return transport
}

type h2Path struct {
	t        *testing.T
	dir      string
	logs     *syncBuffer
	proxy    *httptest.Server
	capture  *Capture
	client   *http.Transport
	upstream *httptest.Server
	closed   bool
}

func newH2Path(t *testing.T, front, back wire, upstream http.Handler) *h2Path {
	t.Helper()
	policy, err := redact.ParsePolicy([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redact.NewEngine(policy, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)

	p := &h2Path{t: t, dir: filepath.Join(t.TempDir(), "traffic"), logs: &syncBuffer{}}
	p.upstream = startOn(t, back, upstream)
	target, err := url.Parse(p.upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Upstream: target,
		Dir:      p.dir,
		Engine:   engine,
		Logger:   slog.New(slog.NewTextHandler(p.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	switch back {
	case wireH2C:
		cfg.UpstreamH2C = true
	case wireTLSH2:
		pool := x509.NewCertPool()
		pool.AddCert(p.upstream.Certificate())
		cfg.UpstreamTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	p.capture, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.proxy = startOn(t, front, p.capture)
	p.client = clientFor(front, p.proxy)
	t.Cleanup(p.client.CloseIdleConnections)
	t.Cleanup(p.close)
	return p
}

func (p *h2Path) close() {
	p.t.Helper()
	if p.closed {
		return
	}
	p.closed = true
	p.proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.capture.Close(ctx); err != nil {
		p.t.Errorf("Close: %v", err)
	}
}

func (p *h2Path) records() []*traffic.Record {
	p.t.Helper()
	p.close()
	h := &harness{t: p.t, dir: p.dir, logs: p.logs, closed: true, capture: p.capture}
	return h.records()
}

func (p *h2Path) do(ctx context.Context, method, target string, body io.Reader, header map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.proxy.URL+target, body)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return p.client.RoundTrip(req)
}

// The whole point of these tests: every combination is real, and each end
// confirms the protocol it actually saw.
func TestEveryProtocolCombinationForwardsAndRecords(t *testing.T) {
	wires := []wire{wireHTTP1, wireH2C, wireTLSH2}
	for _, front := range wires {
		for _, back := range wires {
			t.Run(string(front)+"-to-"+string(back), func(t *testing.T) {
				secret := sentinel(t)
				var upstreamMajor int
				var upstreamBody string
				p := newH2Path(t, front, back, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamMajor = r.ProtoMajor
					data, _ := io.ReadAll(r.Body)
					upstreamBody = string(data)
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"user":{"email":%q},"ok":true}`, secret)
				}))
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				resp, err := p.do(ctx, http.MethodPost, "/orders?token="+secret, strings.NewReader(`{"password":"`+secret+`","sku":"a"}`), map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer " + secret,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				got, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}

				wantFront, wantBack := 1, 1
				if front != wireHTTP1 {
					wantFront = 2
				}
				if back != wireHTTP1 {
					wantBack = 2
				}
				if resp.ProtoMajor != wantFront {
					t.Fatalf("client spoke HTTP/%d, want %d", resp.ProtoMajor, wantFront)
				}
				if upstreamMajor != wantBack {
					t.Fatalf("upstream saw HTTP/%d, want %d", upstreamMajor, wantBack)
				}
				if !strings.Contains(string(got), secret) || !strings.Contains(upstreamBody, secret) {
					t.Fatalf("live traffic was altered: response %q, upstream %q", got, upstreamBody)
				}

				records := p.records()
				if len(records) != 1 {
					t.Fatalf("records = %d", len(records))
				}
				rec := records[0]
				wantProtocol := traffic.ProtocolHTTP11
				if front != wireHTTP1 {
					wantProtocol = traffic.ProtocolHTTP2
				}
				if rec.Protocol != wantProtocol {
					t.Fatalf("protocol = %s, want %s", rec.Protocol, wantProtocol)
				}
				if rec.Response == nil || !strings.Contains(string(rec.Response.Body.Data), `"ok":true`) {
					t.Fatalf("response = %+v", rec.Response)
				}
				h := &harness{t: t, dir: p.dir, logs: p.logs, closed: true}
				h.assertNoSecret(secret)
			})
		}
	}
}

func TestHTTP2TrailersAreForwardedAndRedacted(t *testing.T) {
	secret := sentinel(t)
	p := newH2Path(t, wireH2C, wireH2C, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Trailer", "X-Checksum")
		_, _ = io.WriteString(w, `{}`)
		w.Header().Set("X-Checksum", "abc")
		// Not announced in advance, which only trailers-capable protocols allow.
		w.Header().Set(http.TrailerPrefix+"Set-Cookie", "sid="+secret)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := p.do(ctx, http.MethodGet, "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %d", resp.ProtoMajor)
	}
	if resp.Trailer.Get("X-Checksum") != "abc" || !strings.Contains(resp.Trailer.Get("Set-Cookie"), secret) {
		t.Fatalf("client trailers = %v", resp.Trailer)
	}
	records := p.records()
	if len(records) != 1 || !hasString(records[0].Response.Trailers["X-Checksum"], "abc") {
		t.Fatalf("records = %+v", records)
	}
	if got := records[0].Response.Trailers["Set-Cookie"]; len(got) != 1 || got[0] != redact.Placeholder {
		t.Fatalf("Set-Cookie trailer = %v", got)
	}
	h := &harness{t: t, dir: p.dir, logs: p.logs, closed: true}
	h.assertNoSecret(secret)
}

func TestHTTP2StreamingIsNotBuffered(t *testing.T) {
	release := make(chan struct{})
	p := newH2Path(t, wireH2C, wireH2C, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"first":`)
		_ = http.NewResponseController(w).Flush()
		<-release
		_, _ = io.WriteString(w, `1}`)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := p.do(ctx, http.MethodGet, "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	first := make([]byte, 9)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatalf("first chunk must arrive while upstream is still writing: %v", err)
	}
	close(release)
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
}

// ReverseProxy always flushes responses of unknown length, so only a declared
// Content-Length can show whether the proxy holds back bytes the upstream flushed.
func TestSlowResponseWithKnownLengthIsNotHeldBack(t *testing.T) {
	for _, w := range []wire{wireHTTP1, wireH2C} {
		t.Run(string(w), func(t *testing.T) {
			release := make(chan struct{})
			p := newH2Path(t, w, w, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rw.Header().Set("Content-Type", "application/json")
				rw.Header().Set("Content-Length", "11")
				_, _ = io.WriteString(rw, `{"first":`)
				_ = http.NewResponseController(rw).Flush()
				<-release
				_, _ = io.WriteString(rw, `1}`)
			}))
			defer close(release)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			resp, err := p.do(ctx, http.MethodGet, "/", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			first := make([]byte, 9)
			if _, err := io.ReadFull(resp.Body, first); err != nil {
				t.Fatalf("flushed bytes must reach the client while upstream is still writing: %v", err)
			}
		})
	}
}

func TestHTTP2ClientCancellationResetsTheUpstreamStream(t *testing.T) {
	started := make(chan struct{})
	upstreamCanceled := make(chan struct{})
	p := newH2Path(t, wireH2C, wireH2C, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(upstreamCanceled)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		resp, err := p.do(ctx, http.MethodGet, "/", nil, nil)
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
	records := p.records()
	if len(records) != 1 || records[0].Outcome.Transport != traffic.TransportClientCanceled {
		t.Fatalf("records = %+v", records)
	}
}

func TestHTTP2UpstreamAbortIsVisibleToClientAndRecorded(t *testing.T) {
	p := newH2Path(t, wireH2C, wireH2C, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"partial":`)
		_ = http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := p.do(ctx, http.MethodGet, "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("client must see the broken stream")
	}
	records := p.records()
	if len(records) != 1 || records[0].Outcome.Transport != traffic.TransportUpstreamAbort || records[0].Response.Body.State != traffic.BodyTruncated {
		t.Fatalf("records = %+v", records)
	}
}

// Concurrent streams share one connection in HTTP/2, so a stuck stream must not
// hold up the others on either side of the proxy.
func TestHTTP2StreamsAreMultiplexedWithoutInterference(t *testing.T) {
	release := make(chan struct{})
	hung := make(chan struct{})
	p := newH2Path(t, wireH2C, wireH2C, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang" {
			close(hung)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() {
		resp, err := p.do(ctx, http.MethodGet, "/hang", nil, nil)
		if err != nil {
			t.Error(err)
			return
		}
		_ = resp.Body.Close()
	})
	<-hung
	var inner sync.WaitGroup
	for i := range 100 {
		inner.Go(func() {
			resp, err := p.do(ctx, http.MethodGet, fmt.Sprintf("/fast/%d", i), nil, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if _, err := io.ReadAll(resp.Body); err != nil {
				t.Error(err)
			}
		})
	}
	inner.Wait()
	close(release)
	wg.Wait()
	if records := p.records(); len(records) != 101 {
		t.Fatalf("records = %d", len(records))
	}
}

func TestUpstreamH2CDoesNotFallBackToHTTP1(t *testing.T) {
	policy, err := redact.ParsePolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redact.NewEngine(policy, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := New(Config{Upstream: target, Dir: t.TempDir(), Engine: engine, UpstreamH2C: true})
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(capture)
	defer proxy.Close()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = capture.Close(ctx)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxy.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want a gateway error rather than an HTTP/1.1 fallback", resp.StatusCode)
	}
}

func TestUpstreamH2CRequiresPlainHTTP(t *testing.T) {
	h := newHarness(t, http.NotFoundHandler())
	target, err := url.Parse("https://upstream.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Upstream: target, Dir: t.TempDir(), Engine: h.capture.engine, UpstreamH2C: true}); err == nil {
		t.Fatal("want error")
	}
}
