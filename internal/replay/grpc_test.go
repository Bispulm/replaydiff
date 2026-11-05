package replay

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/Bispulm/replaydiff/internal/fixture"
	"github.com/Bispulm/replaydiff/internal/grpcwire"
	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

const (
	rpcGetOrder    = "/fixture.orders.v1.OrderService/GetOrder"
	rpcCreateOrder = "/fixture.orders.v1.OrderService/CreateOrder"
	rpcWatchOrders = "/fixture.orders.v1.OrderService/WatchOrders"
)

func orderSet(t *testing.T) *protoset.Set {
	t.Helper()
	set, err := protoset.Parse(fixture.DescriptorSet())
	if err != nil {
		t.Fatal(err)
	}
	return set
}

type grpcTarget struct {
	url     string
	service *fixture.GRPCService
	server  *grpc.Server
}

// startGRPCTarget runs the fixture's real gRPC server, which speaks HTTP/2 only.
func startGRPCTarget(t *testing.T, variant fixture.Variant, instance string) *grpcTarget {
	t.Helper()
	service, err := fixture.NewGRPC(fixture.Options{Variant: variant, Instance: instance})
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := service.Server()
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return &grpcTarget{url: "http://" + listener.Addr().String(), service: service, server: server}
}

func grpcCluster(t *testing.T) (a, b, c *grpcTarget, cfg Config) {
	t.Helper()
	a = startGRPCTarget(t, fixture.Baseline, "a")
	b = startGRPCTarget(t, fixture.Baseline, "b")
	c = startGRPCTarget(t, fixture.Candidate, "c")
	cfg = Config{
		BaselineA:      TargetConfig{URL: a.url},
		BaselineB:      TargetConfig{URL: b.url},
		Candidate:      TargetConfig{URL: c.url},
		AllowedOrigins: []string{a.url, b.url, c.url},
		H2C:            true,
		AllowRPCs:      []string{rpcGetOrder},
		Descriptors:    orderSet(t),
	}
	return a, b, c, cfg
}

func requestBytes(t *testing.T, set *protoset.Set, name, jsonText string) []byte {
	t.Helper()
	descriptor, err := set.MessageByURL("type.googleapis.com/fixture.orders.v1." + name)
	if err != nil {
		t.Fatal(err)
	}
	m := dynamicpb.NewMessage(descriptor)
	if err := protojson.Unmarshal([]byte(jsonText), m); err != nil {
		t.Fatal(err)
	}
	data, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func grpcSpec(t *testing.T, set *protoset.Set, rpc, requestJSON string) spec {
	t.Helper()
	request := "GetOrderRequest"
	if rpc == rpcCreateOrder {
		request = "CreateOrderRequest"
	}
	data := requestBytes(t, set, request, requestJSON)
	body := traffic.Body{State: traffic.BodyPresent, ContentType: "application/grpc", Data: data}
	if len(data) == 0 {
		body = traffic.Body{State: traffic.BodyEmpty, ContentType: "application/grpc", ObservedBytes: grpcwire.HeaderSize}
	}
	return spec{
		method:     http.MethodPost,
		path:       rpc,
		rpc:        rpc,
		protocol:   traffic.ProtocolGRPC,
		descriptor: set.Digest(),
		headers:    map[string][]string{"Content-Type": {"application/grpc"}, "Te": {"trailers"}, "Grpc-Timeout": {"999S"}, "Grpc-Accept-Encoding": {"gzip"}},
		body:       body,
	}
}

func TestUnaryGRPCIsReplayedToEveryTargetOverHTTP2(t *testing.T) {
	a, b, c, cfg := grpcCluster(t)
	set := cfg.Descriptors
	summary, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{
		grpcSpec(t, set, rpcGetOrder, `{"id":"ord-1"}`),
		grpcSpec(t, set, rpcGetOrder, `{"id":"ord-missing"}`),
	})))
	if summary.Replayed != 2 || !summary.Complete() {
		t.Fatalf("summary = %+v, problems = %v", summary, summary.Problems())
	}
	for _, target := range []*grpcTarget{a, b, c} {
		if got := target.service.Stats().Requests; got != 2 {
			t.Fatalf("target saw %d requests", got)
		}
	}
	byID := map[uint64]*RecordResult{}
	for _, r := range results {
		byID[r.Seq] = r
	}
	found := byID[1].Calls[RoleCandidate]
	if found.Proto != "HTTP/2.0" || found.GRPCStatus == nil || *found.GRPCStatus != 0 || found.Status != http.StatusOK {
		t.Fatalf("call = %+v", found)
	}
	frames, err := grpcwire.ParseFrames(found.Body)
	if err != nil || len(frames) != 1 || len(frames[0].Payload) == 0 {
		t.Fatalf("response body = %v, %v", frames, err)
	}
	if byID[1].RPC != rpcGetOrder {
		t.Fatalf("result RPC = %q", byID[1].RPC)
	}
	missingA, missingC := byID[2].Calls[RoleBaselineA], byID[2].Calls[RoleCandidate]
	if *missingA.GRPCStatus != 5 || *missingC.GRPCStatus != 13 {
		t.Fatalf("statuses: baseline %d, candidate %d", *missingA.GRPCStatus, *missingC.GRPCStatus)
	}
	if got := summary.Targets["candidate"].GRPCStatuses["INTERNAL"]; got != 1 {
		t.Fatalf("grpc statuses = %+v", summary.Targets["candidate"].GRPCStatuses)
	}
}

// gRPC is POST whatever the method does. Only an explicit list of RPCs makes it eligible.
func TestOnlyAllowedRPCsAreReplayed(t *testing.T) {
	a, _, _, cfg := grpcCluster(t)
	cfg.AllowMethods = []string{http.MethodPost}
	set := cfg.Descriptors
	summary, _ := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{
		grpcSpec(t, set, rpcCreateOrder, `{"sku":"sku-1"}`),
		grpcSpec(t, set, rpcGetOrder, `{"id":"ord-1"}`),
	})))
	if a.service.Stats().Mutations != 0 {
		t.Fatal("a mutating RPC was replayed")
	}
	if summary.Skipped[SkipRPCNotAllowed] != 1 || summary.Replayed != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestRecordsFromAnotherSchemaAreSkipped(t *testing.T) {
	_, _, _, cfg := grpcCluster(t)
	stale := grpcSpec(t, cfg.Descriptors, rpcGetOrder, `{"id":"ord-1"}`)
	stale.descriptor = "00000000000000000000000000000000"
	summary, _ := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{stale})))
	if summary.Skipped[SkipDescriptorMismatch] != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestEmptyRequestMessageIsSentAsOneEmptyFrame(t *testing.T) {
	_, _, c, cfg := grpcCluster(t)
	summary, results := mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{grpcSpec(t, cfg.Descriptors, rpcGetOrder, `{}`)})))
	if summary.Replayed != 1 || c.service.Stats().Requests != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if status := results[0].Calls[RoleCandidate].GRPCStatus; status == nil || *status != 0 {
		t.Fatalf("status = %v", status)
	}
}

// The replay's own timeout is what targets should see, not the deadline in the recording.
func TestGRPCTimeoutComesFromTheReplayConfiguration(t *testing.T) {
	deadlines := make(chan time.Duration, 3)
	c := newCluster(t, nil)
	for _, target := range []*fakeTarget{c.a, c.b, c.c} {
		target.Close()
	}
	record := func(w http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("Grpc-Timeout")
		unit := map[byte]time.Duration{'n': time.Nanosecond, 'u': time.Microsecond, 'm': time.Millisecond, 'S': time.Second, 'M': time.Minute, 'H': time.Hour}[value[len(value)-1]]
		var n int64
		for _, d := range value[:len(value)-1] {
			n = n*10 + int64(d-'0')
		}
		deadlines <- time.Duration(n) * unit
		if r.Header.Get("Te") != "trailers" || r.Header.Get("Grpc-Accept-Encoding") != "" {
			deadlines <- -1
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Header().Set("Grpc-Status", "0")
	}
	a, b, cand := newH2CTarget(t, record), newH2CTarget(t, record), newH2CTarget(t, record)
	cfg := clusterConfig(a, b, cand)
	cfg.H2C = true
	cfg.Timeout = 3 * time.Second
	cfg.AllowRPCs = []string{rpcGetOrder}
	cfg.Descriptors = orderSet(t)
	mustRun(t, mustEngine(t, cfg), scan(t, writeDataset(t, []spec{grpcSpec(t, cfg.Descriptors, rpcGetOrder, `{"id":"x"}`)})))
	close(deadlines)
	count := 0
	for d := range deadlines {
		if d != 3*time.Second {
			t.Fatalf("deadline = %v, want the configured 3s, with te: trailers and no accept-encoding", d)
		}
		count++
	}
	if count != 3 {
		t.Fatalf("deadlines seen = %d", count)
	}
}

func TestGRPCConfigurationIsValidated(t *testing.T) {
	_, _, _, base := grpcCluster(t)
	for name, adjust := range map[string]func(*Config){
		"rpcs without descriptors": func(cfg *Config) { cfg.Descriptors = nil },
		"unknown rpc":              func(cfg *Config) { cfg.AllowRPCs = []string{"/fixture.orders.v1.OrderService/Nope"} },
		"streaming rpc":            func(cfg *Config) { cfg.AllowRPCs = []string{rpcWatchOrders} },
		"http1 targets":            func(cfg *Config) { cfg.H2C = false },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			adjust(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("want error")
			}
		})
	}
}
