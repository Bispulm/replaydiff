package replay

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bispulm/replaydiff/internal/traffic"
)

func h2cOnly() *http.Protocols {
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	return p
}

// newH2CTarget is a real server that accepts only HTTP/2 over cleartext, so an
// HTTP/1.1 fallback can't pass by accident.
func newH2CTarget(t *testing.T, handler http.HandlerFunc) *fakeTarget {
	t.Helper()
	target := &fakeTarget{handler: handler}
	target.Server = httptest.NewUnstartedServer(target.record())
	target.Config.Protocols = h2cOnly()
	target.Start()
	t.Cleanup(target.Close)
	return target
}

func newTLSTarget(t *testing.T, handler http.HandlerFunc) *fakeTarget {
	t.Helper()
	target := &fakeTarget{handler: handler}
	target.Server = httptest.NewUnstartedServer(target.record())
	target.EnableHTTP2 = true
	target.StartTLS()
	t.Cleanup(target.Close)
	return target
}

func clusterConfig(a, b, c *fakeTarget) Config {
	return Config{
		BaselineA:      TargetConfig{URL: a.URL},
		BaselineB:      TargetConfig{URL: b.URL},
		Candidate:      TargetConfig{URL: c.URL},
		AllowedOrigins: []string{a.URL, b.URL, c.URL},
	}
}

func TestH2CReplayIsRealHTTP2(t *testing.T) {
	reply := func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "reply") }
	a, b, c := newH2CTarget(t, reply), newH2CTarget(t, reply), newH2CTarget(t, reply)
	cfg := clusterConfig(a, b, c)
	cfg.H2C = true
	summary, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{{path: "/one", query: "x=1"}})))

	for _, target := range []*fakeTarget{a, b, c} {
		seen := target.seen()
		if len(seen) != 1 || seen[0].ProtoMajor != 2 || seen[0].Path != "/one" || seen[0].Query != "x=1" {
			t.Fatalf("target saw %+v", seen)
		}
	}
	for _, call := range results[0].Calls {
		if call.Outcome != CallOK || call.Proto != "HTTP/2.0" || string(call.Body) != "reply" {
			t.Fatalf("call = %+v", call)
		}
	}
	if got := summary.Targets["candidate"].Protocols["HTTP/2.0"]; got != 1 {
		t.Fatalf("targets = %+v", summary.Targets["candidate"])
	}
}

func TestTLSReplayNegotiatesHTTP2(t *testing.T) {
	a, b, c := newTLSTarget(t, nil), newTLSTarget(t, nil), newTLSTarget(t, nil)
	pool := x509.NewCertPool()
	for _, target := range []*fakeTarget{a, b, c} {
		pool.AddCert(target.Certificate())
	}
	cfg := clusterConfig(a, b, c)
	cfg.TLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	_, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{{path: "/one"}})))
	for _, target := range []*fakeTarget{a, b, c} {
		if seen := target.seen(); len(seen) != 1 || seen[0].ProtoMajor != 2 {
			t.Fatalf("target saw %+v", seen)
		}
	}
	if got := results[0].Calls[RoleCandidate].Proto; got != "HTTP/2.0" {
		t.Fatalf("proto = %q", got)
	}
}

func TestUntrustedCertificateFailsInsteadOfConnecting(t *testing.T) {
	a, b, c := newTLSTarget(t, nil), newTLSTarget(t, nil), newTLSTarget(t, nil)
	summary, results := mustRun(t, mustEngine(t, clusterConfig(a, b, c)), scan(t, writeDataset(t, []spec{{path: "/one"}})))
	if got := results[0].Calls[RoleBaselineA].Outcome; got != CallConnectionError {
		t.Fatalf("outcome = %s", got)
	}
	if len(a.seen()) != 0 {
		t.Fatal("a target with an untrusted certificate received a request")
	}
	if summary.Complete() {
		t.Fatal("evidence can't be complete")
	}
}

func TestH2CRequestBodyHasACorrectLength(t *testing.T) {
	a, b, c := newH2CTarget(t, nil), newH2CTarget(t, nil), newH2CTarget(t, nil)
	cfg := clusterConfig(a, b, c)
	cfg.H2C = true
	cfg.AllowMethods = []string{http.MethodPost}
	stored := []byte(`{"sku":"a"}`)
	specs := []spec{{
		method:  http.MethodPost,
		headers: map[string][]string{"Content-Type": {"application/json"}},
		body:    traffic.Body{State: traffic.BodyPresent, Data: stored},
	}}
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, specs)))
	seen := c.seen()
	if len(seen) != 1 || seen[0].Body != string(stored) || seen[0].ContentLength != int64(len(stored)) {
		t.Fatalf("seen = %+v", seen)
	}
}

// With h2c selected, a target that speaks only HTTP/1.1 must fail. Falling back
// would report HTTP/2 results from an HTTP/1.1 run.
func TestH2CDoesNotFallBackToHTTP1(t *testing.T) {
	c := newCluster(t, nil)
	cfg := c.config()
	cfg.H2C = true
	summary, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{{path: "/one"}})))
	if got := results[0].Calls[RoleCandidate].Outcome; got == CallOK {
		t.Fatalf("outcome = %s", got)
	}
	// An HTTP/1 server parses the HTTP/2 preface as a request for "*", so the
	// handler may run for that. The recorded path must never arrive.
	for _, req := range c.c.seen() {
		if req.Path == "/one" {
			t.Fatalf("the request reached an HTTP/1 target: %+v", req)
		}
	}
	if summary.Complete() {
		t.Fatal("evidence can't be complete when no baseline call succeeded")
	}
}

func TestH2CCannotBeCombinedWithTLSTargets(t *testing.T) {
	cfg := Config{
		BaselineA:      TargetConfig{URL: "https://a.example.test"},
		BaselineB:      TargetConfig{URL: "https://b.example.test"},
		Candidate:      TargetConfig{URL: "https://c.example.test"},
		AllowedOrigins: []string{"https://a.example.test", "https://b.example.test", "https://c.example.test"},
		H2C:            true,
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("want error")
	}
}

func TestPlainHTTPTargetsUseHTTP1ByDefault(t *testing.T) {
	c := newCluster(t, nil)
	_, results := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, []spec{{path: "/one"}})))
	if got := results[0].Calls[RoleCandidate].Proto; got != "HTTP/1.1" {
		t.Fatalf("proto = %q", got)
	}
}

func TestH2CTimeoutIsAnOutcomeAndCancelsTheStream(t *testing.T) {
	canceled := make(chan struct{})
	hang := func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(canceled)
	}
	a, b, c := newH2CTarget(t, nil), newH2CTarget(t, nil), newH2CTarget(t, hang)
	cfg := clusterConfig(a, b, c)
	cfg.H2C = true
	cfg.Timeout = 80 * time.Millisecond
	_, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{{path: "/hang"}})))
	if got := results[0].Calls[RoleCandidate].Outcome; got != CallTimeout {
		t.Fatalf("outcome = %s", got)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the timeout didn't cancel the stream on the target")
	}
}

func TestH2CSessionOrderHolds(t *testing.T) {
	var next atomic.Int64
	var violations atomic.Int64
	ordered := func(_ http.ResponseWriter, r *http.Request) {
		want := next.Load()
		if !strings.HasSuffix(r.URL.Path, "/"+string(rune('a'+want))) {
			violations.Add(1)
		}
		time.Sleep(2 * time.Millisecond)
		next.Add(1)
	}
	a, b, c := newH2CTarget(t, nil), newH2CTarget(t, nil), newH2CTarget(t, ordered)
	cfg := clusterConfig(a, b, c)
	cfg.H2C = true
	session := strings.Repeat("d", 32)
	specs := []spec{{session: session, path: "/s/a"}, {session: session, path: "/s/b"}, {session: session, path: "/s/c"}, {session: session, path: "/s/d"}}
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, specs)))
	if violations.Load() != 0 || next.Load() != 4 {
		t.Fatalf("violations = %d, handled = %d", violations.Load(), next.Load())
	}
}

// rawH2Server speaks HTTP/2 frames directly, because net/http's server can't be
// made to refuse a stream or send GOAWAY on demand. It runs firstStream on the
// first request it sees and answers every later one with 200.
type rawH2Server struct {
	listener net.Listener
	requests atomic.Int64
}

func h2Frame(c net.Conn, frameType, flags byte, stream uint32, payload []byte) {
	header := make([]byte, 9)
	header[0], header[1], header[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	header[3], header[4] = frameType, flags
	binary.BigEndian.PutUint32(header[5:], stream)
	_, _ = c.Write(append(header, payload...))
}

func newRawH2Server(t *testing.T, firstStream func(net.Conn, uint32)) *rawH2Server {
	t.Helper()
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &rawH2Server{listener: listener}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(conn, firstStream)
		}
	}()
	return server
}

func (s *rawH2Server) URL() string { return "http://" + s.listener.Addr().String() }

func (s *rawH2Server) serve(conn net.Conn, firstStream func(net.Conn, uint32)) {
	defer func() { _ = conn.Close() }()
	const (
		frameHeaders  = 0x1
		frameSettings = 0x4
		flagAck       = 0x1
		flagEndStream = 0x1
		flagEndHeader = 0x4
		// HPACK static table index 8 is ":status: 200".
		statusOK = 0x88
	)
	reader := bufio.NewReader(conn)
	if _, err := io.ReadFull(reader, make([]byte, 24)); err != nil {
		return
	}
	h2Frame(conn, frameSettings, 0, 0, nil)
	for {
		header := make([]byte, 9)
		if _, err := io.ReadFull(reader, header); err != nil {
			return
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		if _, err := io.ReadFull(reader, make([]byte, length)); err != nil {
			return
		}
		stream := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
		switch header[3] {
		case frameSettings:
			if header[4]&flagAck == 0 {
				h2Frame(conn, frameSettings, flagAck, 0, nil)
			}
		case frameHeaders:
			if s.requests.Add(1) == 1 {
				firstStream(conn, stream)
				continue
			}
			h2Frame(conn, frameHeaders, flagEndStream|flagEndHeader, stream, []byte{statusOK})
		}
	}
}

func refuseStream(c net.Conn, stream uint32) {
	const frameRSTStream, refusedStream = 0x3, 0x7
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, refusedStream)
	h2Frame(c, frameRSTStream, 0, stream, payload)
}

func goAwayUnprocessed(c net.Conn, _ uint32) {
	const frameGoAway = 0x7
	h2Frame(c, frameGoAway, 0, 0, make([]byte, 8))
	_ = c.Close()
}

// Go's HTTP/2 client resends a request when the server says it wasn't processed,
// and that can't be turned off. It must at least not be invisible.
func TestHTTP2ResendsAreCountedAndReported(t *testing.T) {
	for name, firstStream := range map[string]func(net.Conn, uint32){
		"refused stream": refuseStream,
		"goaway":         goAwayUnprocessed,
	} {
		t.Run(name, func(t *testing.T) {
			raw := newRawH2Server(t, firstStream)
			a, b := newH2CTarget(t, nil), newH2CTarget(t, nil)
			cfg := Config{
				BaselineA:      TargetConfig{URL: a.URL},
				BaselineB:      TargetConfig{URL: b.URL},
				Candidate:      TargetConfig{URL: raw.URL()},
				AllowedOrigins: []string{a.URL, b.URL, raw.URL()},
				H2C:            true,
			}
			summary, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{{path: "/one"}})))
			if got := raw.requests.Load(); got != 2 {
				t.Fatalf("server saw %d attempts, want the resend this test exists to observe", got)
			}
			call := results[0].Calls[RoleCandidate]
			if call.Attempts != 2 || call.Outcome != CallOK {
				t.Fatalf("call = %+v", call)
			}
			if got := summary.Targets["candidate"].Resends; got != 1 {
				t.Fatalf("resends = %d", got)
			}
			if got := summary.Targets["baseline-a"].Resends; got != 0 {
				t.Fatalf("baseline resends = %d", got)
			}
		})
	}
}

func TestSingleAttemptIsReportedAsOne(t *testing.T) {
	c := newCluster(t, nil)
	summary, results := mustRun(t, mustEngine(t, c.config()), scan(t, writeDataset(t, []spec{{path: "/one"}})))
	if got := results[0].Calls[RoleCandidate].Attempts; got != 1 {
		t.Fatalf("attempts = %d", got)
	}
	if got := summary.Targets["candidate"].Resends; got != 0 {
		t.Fatalf("resends = %d", got)
	}
}
