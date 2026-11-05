package fixture

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

type grpcDeployment struct {
	a, b, candidate *grpc.ClientConn
	aService        *GRPCService
}

func startGRPC(t *testing.T, opts Options) (*grpc.ClientConn, *GRPCService) {
	t.Helper()
	service, err := NewGRPC(opts)
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
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, service
}

func deployGRPC(t *testing.T) grpcDeployment {
	t.Helper()
	a, aService := startGRPC(t, Options{Variant: Baseline, Instance: "a"})
	b, _ := startGRPC(t, Options{Variant: Baseline, Instance: "b"})
	c, _ := startGRPC(t, Options{Variant: Candidate, Instance: "c"})
	return grpcDeployment{a: a, b: b, candidate: c, aService: aService}
}

func message(t *testing.T, name string) *dynamicpb.Message {
	t.Helper()
	descriptor, err := Descriptors().FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		t.Fatal(err)
	}
	return dynamicpb.NewMessage(descriptor.(protoreflect.MessageDescriptor))
}

func call(t *testing.T, conn *grpc.ClientConn, method, request string, requestJSON string) (map[string]any, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := message(t, "fixture.orders.v1."+request)
	if err := protojson.Unmarshal([]byte(requestJSON), req); err != nil {
		t.Fatal(err)
	}
	reply := message(t, "fixture.orders.v1."+map[string]string{"GetOrder": "Order", "CreateOrder": "Order", "GetCatalog": "Catalog"}[method])
	if err := conn.Invoke(ctx, "/fixture.orders.v1.OrderService/"+method, req, reply); err != nil {
		return nil, err
	}
	return messageMap(t, reply), nil
}

func messageMap(t *testing.T, m proto.Message) map[string]any {
	t.Helper()
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := jsonUnmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGRPCBaselinesAgreeExceptOnNoise(t *testing.T) {
	d := deployGRPC(t)
	a, err := call(t, d.a, "GetOrder", "GetOrderRequest", `{"id":"ord-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := call(t, d.b, "GetOrder", "GetOrderRequest", `{"id":"ord-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, noise := range []string{"server_time", "request_id"} {
		if a[noise] == b[noise] {
			t.Errorf("%s matches on both baselines: %v", noise, a[noise])
		}
	}
	if !equalExcept(a, b, "server_time", "request_id") {
		t.Fatalf("baselines differ outside noise:\n%v\n%v", a, b)
	}
}

func TestGRPCCandidateRegressions(t *testing.T) {
	d := deployGRPC(t)
	base, err := call(t, d.a, "GetOrder", "GetOrderRequest", `{"id":"ord-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := call(t, d.candidate, "GetOrder", "GetOrderRequest", `{"id":"ord-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base["note"]; !ok {
		t.Error("baseline must set the optional note")
	}
	if _, ok := cand["note"]; ok {
		t.Error("candidate must leave the optional note unset")
	}
	if _, ok := base["shipment"]; !ok {
		t.Error("baseline must set shipment")
	}
	if _, ok := cand["shipment"]; ok {
		t.Error("candidate must leave shipment unset")
	}
	if base["card_last4"] == nil || cand["card_last4"] != nil || cand["invoice_id"] == nil {
		t.Errorf("oneof: baseline %v/%v, candidate %v/%v", base["card_last4"], base["invoice_id"], cand["card_last4"], cand["invoice_id"])
	}
	if base["status"] == cand["status"] {
		t.Error("candidate must change the status enum")
	}
	baseLabels, candLabels := base["labels"].(map[string]any), cand["labels"].(map[string]any)
	if _, ok := baseLabels["region"]; !ok {
		t.Error("baseline must have the region label")
	}
	if _, ok := candLabels["region"]; ok {
		t.Error("candidate must drop the region label")
	}
	if _, ok := candLabels["experiment"]; !ok {
		t.Error("candidate must add the experiment label")
	}

	for name, tc := range map[string]struct {
		conn *grpc.ClientConn
		id   string
		want codes.Code
	}{
		"baseline missing order":    {d.a, "ord-missing", codes.NotFound},
		"candidate missing order":   {d.candidate, "ord-missing", codes.Internal},
		"baseline available":        {d.a, "ord-unavailable", codes.OK},
		"candidate now unavailable": {d.candidate, "ord-unavailable", codes.Unavailable},
	} {
		_, err := call(t, tc.conn, "GetOrder", "GetOrderRequest", `{"id":"`+tc.id+`"}`)
		if got := status.Code(err); got != tc.want {
			t.Errorf("%s: code = %s, want %s", name, got, tc.want)
		}
	}
}

func TestGRPCControlRouteHasNoRegression(t *testing.T) {
	d := deployGRPC(t)
	base, err := call(t, d.a, "GetCatalog", "GetCatalogRequest", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := call(t, d.candidate, "GetCatalog", "GetCatalogRequest", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if !equalExcept(base, cand, "generated_at", "request_id") {
		t.Fatalf("catalog differs:\n%v\n%v", base, cand)
	}
}

func TestGRPCMutationsAreCounted(t *testing.T) {
	d := deployGRPC(t)
	if _, err := call(t, d.a, "CreateOrder", "CreateOrderRequest", `{"sku":"sku-1"}`); err != nil {
		t.Fatal(err)
	}
	if got := d.aService.Stats().Mutations; got != 1 {
		t.Fatalf("mutations = %d", got)
	}
}

func TestGRPCStreamingMethodStreams(t *testing.T) {
	d := deployGRPC(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := d.a.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/fixture.orders.v1.OrderService/WatchOrders")
	if err != nil {
		t.Fatal(err)
	}
	req := message(t, "fixture.orders.v1.GetOrderRequest")
	if err := stream.SendMsg(req); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	count := 0
	for {
		reply := message(t, "fixture.orders.v1.Order")
		err := stream.RecvMsg(reply)
		if err != nil {
			if !errors.Is(err, errEOF) {
				t.Fatal(err)
			}
			break
		}
		count++
	}
	if count < 2 {
		t.Fatalf("received %d messages, want a stream", count)
	}
}

func TestGRPCLargeNumbersArePrecise(t *testing.T) {
	d := deployGRPC(t)
	order, err := call(t, d.a, "GetOrder", "GetOrderRequest", `{"id":"ord-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	// protojson renders int64 as a string precisely so that it isn't rounded.
	if order["total_cents"] != "9007199254740993" {
		t.Fatalf("total_cents = %v", order["total_cents"])
	}
}

func TestDescriptorSetIsEmbeddedAndComplete(t *testing.T) {
	if len(DescriptorSet()) == 0 {
		t.Fatal("no descriptor set")
	}
	if _, err := Descriptors().FindDescriptorByName("google.protobuf.Any"); err != nil {
		t.Fatal("imports must be included:", err)
	}
	if !strings.Contains(string(DescriptorSet()), "OrderService") {
		t.Fatal("service missing")
	}
}
