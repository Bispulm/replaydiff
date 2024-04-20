package capture

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/Bispulm/replaydiff/internal/grpcwire"
	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

const (
	grpcPolicy = `
proto_fields:
  - fixture.orders.v1.GetOrderRequest.auth_token
  - fixture.orders.v1.Customer.email
`
	getOrderRPC = "/fixture.orders.v1.OrderService/GetOrder"
)

func grpcSet(t *testing.T) *protoset.Set {
	t.Helper()
	set, err := protoset.Load("../fixture/proto/orders.binpb")
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func newDynamic(t *testing.T, set *protoset.Set, name string) *dynamicpb.Message {
	t.Helper()
	descriptor, err := set.MessageByURL("type.googleapis.com/fixture.orders.v1." + name)
	if err != nil {
		t.Fatal(err)
	}
	return dynamicpb.NewMessage(descriptor)
}

type orderHandler func(ctx context.Context, request *dynamicpb.Message) (proto.Message, error)

// grpcUpstream is a real grpc-go server whose GetOrder and WatchOrders do what a test says.
func grpcUpstream(t *testing.T, set *protoset.Set, getOrder orderHandler) string {
	t.Helper()
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "fixture.orders.v1.OrderService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "GetOrder",
			Handler: func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				request := newDynamic(t, set, "GetOrderRequest")
				if err := decode(request); err != nil {
					return nil, err
				}
				return getOrder(ctx, request)
			},
		}},
		Streams: []grpc.StreamDesc{{
			StreamName:    "WatchOrders",
			ServerStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				if err := stream.RecvMsg(newDynamic(t, set, "GetOrderRequest")); err != nil {
					return err
				}
				for range 3 {
					if err := stream.SendMsg(orderMessage(t, set, `{"id":"streamed"}`)); err != nil {
						return err
					}
				}
				return nil
			},
		}},
	}, nil)
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return "http://" + listener.Addr().String()
}

func orderMessage(t *testing.T, set *protoset.Set, jsonText string) *dynamicpb.Message {
	t.Helper()
	m := newDynamic(t, set, "Order")
	if err := (protojson.UnmarshalOptions{Resolver: set.Types()}).Unmarshal([]byte(jsonText), m); err != nil {
		t.Fatal(err)
	}
	return m
}

type grpcPath struct {
	*h2Path
	conn *grpc.ClientConn
	set  *protoset.Set
}

// newGRPCPath puts the capture proxy between a real grpc-go client and server, over
// HTTP/2 without TLS on both sides.
func newGRPCPath(t *testing.T, policy string, withDescriptors bool, getOrder orderHandler) *grpcPath {
	t.Helper()
	set := grpcSet(t)
	p, err := redact.ParsePolicy([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	opts := redact.Options{}
	if withDescriptors {
		opts.Descriptors = set
	}
	engine, err := redact.NewEngine(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)

	upstream, err := url.Parse(grpcUpstream(t, set, getOrder))
	if err != nil {
		t.Fatal(err)
	}
	path := &h2Path{t: t, dir: filepath.Join(t.TempDir(), "traffic"), logs: &syncBuffer{}}
	path.capture, err = New(Config{
		Upstream:    upstream,
		UpstreamH2C: true,
		Dir:         path.dir,
		Engine:      engine,
		Logger:      slog.New(slog.NewTextHandler(path.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	path.proxy = startOn(t, wireH2C, path.capture)
	path.client = clientFor(wireH2C, path.proxy)
	t.Cleanup(path.close)

	conn, err := grpc.NewClient(strings.TrimPrefix(path.proxy.URL, "http://"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &grpcPath{h2Path: path, conn: conn, set: set}
}

func (g *grpcPath) getOrder(ctx context.Context, requestJSON string, opts ...grpc.CallOption) (*dynamicpb.Message, error) {
	request := newDynamic(g.t, g.set, "GetOrderRequest")
	if err := protojson.Unmarshal([]byte(requestJSON), request); err != nil {
		g.t.Fatal(err)
	}
	reply := newDynamic(g.t, g.set, "Order")
	err := g.conn.Invoke(ctx, getOrderRPC, request, reply, opts...)
	return reply, err
}

func field(m protoreflect.Message, path ...string) protoreflect.Value {
	for i, name := range path {
		value := m.Get(m.Descriptor().Fields().ByName(protoreflect.Name(name)))
		if i == len(path)-1 {
			return value
		}
		m = value.Message()
	}
	return protoreflect.Value{}
}

func TestUnaryGRPCIsForwardedAndRecordedSanitized(t *testing.T) {
	secret := sentinel(t)
	var upstreamToken string
	g := newGRPCPath(t, grpcPolicy, true, func(_ context.Context, request *dynamicpb.Message) (proto.Message, error) {
		upstreamToken = field(request, "auth_token").String()
		return orderMessage(t, grpcSet(t), `{"id":"ord-1","customer":{"email":"`+secret+`","tier":"gold"},"note":"kept"}`), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+secret, "x-trace-bin", secret, "x-tenant", "t1")
	reply, err := g.getOrder(ctx, `{"id":"ord-1","auth_token":"`+secret+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	if upstreamToken != secret || field(reply, "customer", "email").String() != secret {
		t.Fatal("live traffic must be untouched")
	}

	records := g.records()
	if len(records) != 1 {
		t.Fatalf("records = %d", len(records))
	}
	rec := records[0]
	if rec.Protocol != traffic.ProtocolGRPC || rec.RPC != getOrderRPC || rec.Response == nil || rec.Response.GRPCStatus == nil || *rec.Response.GRPCStatus != 0 {
		t.Fatalf("record = %+v", rec)
	}
	if rec.Descriptor == nil || rec.Descriptor.SetDigest != g.set.Digest() {
		t.Fatalf("descriptor = %+v", rec.Descriptor)
	}
	if rec.Request.Body.State != traffic.BodyPresent || rec.Response.Body.State != traffic.BodyPresent || !rec.Replay.Eligible {
		t.Fatalf("request %+v, response %+v, replay %+v", rec.Request.Body, rec.Response.Body, rec.Replay)
	}
	stored := newDynamic(t, g.set, "Order")
	if err := proto.Unmarshal(rec.Response.Body.Data, stored); err != nil {
		t.Fatalf("stored response isn't a message: %v", err)
	}
	if field(stored, "note").String() != "kept" || field(stored, "customer", "email").String() != redact.Placeholder {
		t.Fatalf("stored = %v", stored)
	}
	if got := rec.Request.Headers["X-Tenant"]; len(got) != 1 || got[0] != "t1" {
		t.Fatalf("ordinary metadata must be kept: %v", rec.Request.Headers)
	}
	h := &harness{t: t, dir: g.dir, logs: g.logs, closed: true}
	h.assertNoSecret(secret)
}

func TestGRPCErrorsAreRecordedWithoutTheirMessage(t *testing.T) {
	secret := sentinel(t)
	g := newGRPCPath(t, grpcPolicy, true, func(context.Context, *dynamicpb.Message) (proto.Message, error) {
		return nil, status.Error(codes.NotFound, "no order for "+secret)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := g.getOrder(ctx, `{"id":"ord-missing"}`)
	if status.Code(err) != codes.NotFound || !strings.Contains(status.Convert(err).Message(), secret) {
		t.Fatalf("the client must see the real status and message: %v", err)
	}
	records := g.records()
	rec := records[0]
	// grpc-go answers an error with no message as Trailers-Only, so the status arrives in
	// the response headers rather than the trailers.
	if rec.Response.GRPCStatus == nil || *rec.Response.GRPCStatus != int(codes.NotFound) || rec.Response.StatusCode != http.StatusOK {
		t.Fatalf("response = %+v", rec.Response)
	}
	if rec.Response.Body.State != traffic.BodyEmpty {
		t.Fatalf("body = %+v", rec.Response.Body)
	}
	h := &harness{t: t, dir: g.dir, logs: g.logs, closed: true}
	h.assertNoSecret(secret)
}

func TestCompressedGRPCMessagesAreStoredDecompressed(t *testing.T) {
	g := newGRPCPath(t, grpcPolicy, true, func(context.Context, *dynamicpb.Message) (proto.Message, error) {
		return orderMessage(t, grpcSet(t), `{"id":"ord-1","note":"`+strings.Repeat("compressible ", 50)+`"}`), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := g.getOrder(ctx, `{"id":"ord-1"}`, grpc.UseCompressor(gzip.Name)); err != nil {
		t.Fatal(err)
	}
	rec := g.records()[0]
	if rec.Request.Body.OriginalEncoding != "gzip" || rec.Request.Body.State != traffic.BodyPresent {
		t.Fatalf("request body = %+v", rec.Request.Body)
	}
	if rec.Response.Body.State != traffic.BodyPresent {
		t.Fatalf("response body = %+v", rec.Response.Body)
	}
	stored := newDynamic(t, g.set, "GetOrderRequest")
	if err := proto.Unmarshal(rec.Request.Body.Data, stored); err != nil || field(stored, "id").String() != "ord-1" {
		t.Fatalf("stored request = %v, err = %v", stored, err)
	}
}

func TestGRPCDeadlineIsForwardedAndCancellationReachesUpstream(t *testing.T) {
	deadlines := make(chan bool, 1)
	g := newGRPCPath(t, grpcPolicy, true, func(ctx context.Context, _ *dynamicpb.Message) (proto.Message, error) {
		_, ok := ctx.Deadline()
		deadlines <- ok
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := g.getOrder(ctx, `{"id":"ord-1"}`)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("err = %v", err)
	}
	if !<-deadlines {
		t.Fatal("the upstream must see the client's deadline, through grpc-timeout")
	}
	waitFor(t, "the exchange to be recorded", func() bool {
		stats := g.capture.Stats()
		return stats.Persisted+int64(len(stats.Dropped)) >= 1
	})
	records := g.records()
	if len(records) != 1 || records[0].Replay.Eligible && records[0].Request.Body.State != traffic.BodyPresent {
		t.Fatalf("records = %+v", records)
	}
}

func TestStreamingGRPCIsForwardedButNotReplayable(t *testing.T) {
	g := newGRPCPath(t, grpcPolicy, true, func(context.Context, *dynamicpb.Message) (proto.Message, error) {
		return nil, errors.New("unused")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := g.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/fixture.orders.v1.OrderService/WatchOrders")
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendMsg(newDynamic(t, g.set, "GetOrderRequest")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	received := 0
	for {
		if err := stream.RecvMsg(newDynamic(t, g.set, "Order")); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
		received++
	}
	if received != 3 {
		t.Fatalf("received %d messages through the proxy", received)
	}
	rec := g.records()[0]
	if rec.Replay.Eligible || rec.Response.Body.Reason != redact.ReasonGRPCStreaming {
		t.Fatalf("record = %+v", rec)
	}
}

func TestGRPCWithoutDescriptorsIsForwardedButNotStored(t *testing.T) {
	secret := sentinel(t)
	g := newGRPCPath(t, "", false, func(context.Context, *dynamicpb.Message) (proto.Message, error) {
		return orderMessage(t, grpcSet(t), `{"id":"`+secret+`"}`), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply, err := g.getOrder(ctx, `{"id":"`+secret+`"}`)
	if err != nil || field(reply, "id").String() != secret {
		t.Fatalf("reply = %v, err = %v", reply, err)
	}
	rec := g.records()[0]
	if rec.Replay.Eligible || rec.Request.Body.Reason != redact.ReasonProtoDescriptorMissing || rec.Descriptor != nil {
		t.Fatalf("record = %+v", rec)
	}
	h := &harness{t: t, dir: g.dir, logs: g.logs, closed: true}
	h.assertNoSecret(secret)
}

// rawGRPC sends a hand-built request over HTTP/2, for inputs a real client won't produce.
func rawGRPC(t *testing.T, g *grpcPath, contentType string, body []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := g.do(ctx, http.MethodPost, getOrderRPC, strings.NewReader(string(body)), map[string]string{"Content-Type": contentType, "Te": "trailers"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
}

func TestMalformedGRPCRequestIsForwardedButNotStored(t *testing.T) {
	secret := sentinel(t)
	g := newGRPCPath(t, grpcPolicy, true, func(context.Context, *dynamicpb.Message) (proto.Message, error) {
		return orderMessage(t, grpcSet(t), `{"id":"x"}`), nil
	})
	rawGRPC(t, g, "application/grpc", append([]byte{0, 0, 0, 1, 0}, []byte(secret)...))
	rec := g.records()[0]
	if rec.Replay.Eligible || rec.Request.Body.State != traffic.BodyOmitted || rec.Request.Body.Reason != redact.ReasonGRPCMalformedFrame {
		t.Fatalf("record = %+v", rec)
	}
	h := &harness{t: t, dir: g.dir, logs: g.logs, closed: true}
	h.assertNoSecret(secret)
}

func TestGRPCWithAnotherCodecIsNotStored(t *testing.T) {
	secret := sentinel(t)
	g := newGRPCPath(t, grpcPolicy, true, func(context.Context, *dynamicpb.Message) (proto.Message, error) {
		return orderMessage(t, grpcSet(t), `{"id":"x"}`), nil
	})
	rawGRPC(t, g, "application/grpc+json", grpcwire.AppendFrame(nil, []byte(`{"id":"`+secret+`"}`), false))
	rec := g.records()[0]
	if rec.Protocol != traffic.ProtocolGRPC || rec.Replay.Eligible || rec.Request.Body.Reason != ReasonGRPCUnsupportedCodec {
		t.Fatalf("record = %+v", rec)
	}
	h := &harness{t: t, dir: g.dir, logs: g.logs, closed: true}
	h.assertNoSecret(secret)
}
