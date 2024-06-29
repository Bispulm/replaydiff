package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/Bispulm/replaydiff/internal/protoset"
)

const (
	orderService      = "/fixture.orders.v1.OrderService/"
	descriptorSetPath = "../../internal/fixture/proto/orders.binpb"
	grpcPolicy        = `
proto_fields:
  - fixture.orders.v1.Customer.email
  - fixture.orders.v1.GetOrderRequest.auth_token
`
)

func deployGRPC(t *testing.T) *slice {
	t.Helper()
	work := t.TempDir()
	s := &slice{
		work:       work,
		trafficDir: filepath.Join(work, "traffic"),
		policy:     writeFile(t, filepath.Join(work, "redact.yaml"), grpcPolicy),
	}
	fixture := func(variant, instance string) *process {
		return start(t, nil, "replaydiff-fixture", "--grpc", "--listen", "127.0.0.1:0", "--variant", variant, "--instance", instance)
	}
	s.captureSvc = fixture("baseline", "capture")
	s.a, s.b, s.c = fixture("baseline", "a"), fixture("baseline", "b"), fixture("candidate", "c")
	s.aURL, s.bURL, s.cURL = s.a.baseURL(t), s.b.baseURL(t), s.c.baseURL(t)
	return s
}

type grpcClient struct {
	t    *testing.T
	set  *protoset.Set
	conn *grpc.ClientConn
	ctx  context.Context
}

func (c *grpcClient) message(name, jsonText string) *dynamicpb.Message {
	c.t.Helper()
	descriptor, err := c.set.MessageByURL("type.googleapis.com/fixture.orders.v1." + name)
	if err != nil {
		c.t.Fatal(err)
	}
	m := dynamicpb.NewMessage(descriptor)
	if err := protojson.Unmarshal([]byte(jsonText), m); err != nil {
		c.t.Fatal(err)
	}
	return m
}

// call makes one unary call and checks the status the service answered with.
func (c *grpcClient) call(method, requestType, replyType, request string, want codes.Code) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	err := c.conn.Invoke(ctx, orderService+method, c.message(requestType, request), c.message(replyType, `{}`))
	if got := status.Code(err); got != want {
		c.t.Fatalf("%s %s: status %v, want %v (%v)", method, request, got, want, err)
	}
}

// captureGRPCTraffic records unary calls on two routes, with enough GetOrder calls to
// evaluate its error rate, plus a call replay must skip and a streaming call capture
// must not store. Credentials go in metadata and in a request field.
func captureGRPCTraffic(t *testing.T, s *slice, secret string) []byte {
	t.Helper()
	proxy := start(t, nil, "replaydiff", "capture", "--listen", "127.0.0.1:0", "--h2c",
		"--upstream", s.captureSvc.baseURL(t), "--upstream-h2c", "--out", s.trafficDir,
		"--redact", s.policy, "--descriptor-set", descriptorSetPath)
	conn, err := grpc.NewClient(strings.TrimPrefix(proxy.baseURL(t), "http://"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	set, err := protoset.Load(descriptorSetPath)
	if err != nil {
		t.Fatal(err)
	}
	client := &grpcClient{t: t, set: set, conn: conn,
		ctx: metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+secret)}
	order := func(id string) string { return `{"id":"` + id + `","auth_token":"` + secret + `"}` }
	for i := 1; i <= 18; i++ {
		client.call("GetOrder", "GetOrderRequest", "Order", order(fmt.Sprintf("ord-%d", i)), codes.OK)
	}
	client.call("GetOrder", "GetOrderRequest", "Order", order("ord-missing"), codes.NotFound)
	client.call("GetOrder", "GetOrderRequest", "Order", order("ord-unavailable"), codes.OK)
	for range 5 {
		client.call("GetCatalog", "GetCatalogRequest", "Catalog", `{}`, codes.OK)
	}
	client.call("CreateOrder", "CreateOrderRequest", "Order", `{"sku":"sku-1"}`, codes.OK)

	stream, err := conn.NewStream(client.ctx, &grpc.StreamDesc{ServerStreams: true}, orderService+"WatchOrders")
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendMsg(client.message("GetOrderRequest", order("ord-1"))); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	for {
		if err := stream.RecvMsg(client.message("Order", `{}`)); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proxy.stop(t); err != nil {
		t.Fatalf("capture exit: %v\n%s", err, proxy.output())
	}
	return []byte(proxy.output())
}

// TestGRPCRegressionsAreDetected is the acceptance test for gRPC, using real processes.
// The expected lists are exact and come from docs/fixtures.md.
func TestGRPCRegressionsAreDetected(t *testing.T) {
	s := deployGRPC(t)
	secret := newSentinel(t)
	captureLogs := captureGRPCTraffic(t, s, secret)
	assertAbsent(t, "capture logs", captureLogs, secret)
	scanDir(t, s.trafficDir, secret)

	inspect := runCommand(t, nil, "replaydiff", "inspect", "--traffic", s.trafficDir, "--descriptor-set", descriptorSetPath)
	if inspect.code != 0 || !strings.Contains(string(inspect.stdout), `"data_proto":{"id":"ord-1"`) {
		t.Fatalf("inspect exit %d: %s\n%s", inspect.code, inspect.stdout, inspect.stderr)
	}
	assertAbsent(t, "inspect output", inspect.stdout, secret)

	reportPath := filepath.Join(s.work, "report.json")
	// The error rate needs 20 GetOrder calls, which is also enough to judge latency, and the
	// fixture seeds no gRPC latency regression. On a busy machine, one slow candidate call
	// out of 20 would be reported, so latency is left out of this test.
	diffConfig := writeFile(t, filepath.Join(s.work, "diff.yaml"), "latency:\n  min_samples: 1000\n")
	run := runCommand(t, nil, "replaydiff", s.runArgs(reportPath, "--target-h2c", "--descriptor-set", descriptorSetPath,
		"--diff-config", diffConfig, "--allow-rpc", orderService+"GetOrder", "--allow-rpc", orderService+"GetCatalog")...)
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("no report (exit %d): %s", run.code, run.stderr)
	}
	assertAbsent(t, "run report", data, secret)
	assertAbsent(t, "run output", append(run.stdout, run.stderr...), secret)
	if run.code != 0 {
		t.Fatalf("run exit %d: %s", run.code, run.stderr)
	}

	var summary reportFile
	var comparison comparisonReport
	var config struct {
		Config struct {
			AllowRPCs        []string `json:"allow_rpcs"`
			DescriptorDigest string   `json:"descriptor_digest"`
		} `json:"config"`
	}
	for _, into := range []any{&summary, &comparison, &config} {
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatal(err)
		}
	}
	set, err := protoset.Load(descriptorSetPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.Config.DescriptorDigest != set.Digest() || len(config.Config.AllowRPCs) != 2 {
		t.Errorf("config = %+v", config.Config)
	}
	// CreateOrder isn't allowed, so its side effect isn't repeated, and the streaming
	// call was never stored.
	wantSkipped := map[string]int{"grpc_method_not_allowed": 1, "request_body_grpc_streaming": 1}
	if summary.Summary.Records != 27 || summary.Summary.Replayed != 25 || !maps.Equal(summary.Summary.Skipped, wantSkipped) {
		t.Errorf("summary = %+v", summary.Summary)
	}

	const getOrder, getCatalog = "POST " + orderService + "GetOrder", "POST " + orderService + "GetCatalog"
	for severity, want := range map[string][]string{
		"breaking": {
			"breaking field_removed " + getOrder + " $.card_last4",
			"breaking field_removed " + getOrder + " $.note",
			"breaking field_removed " + getOrder + " $.shipment",
			"breaking grpc_error_introduced " + getOrder + " ",
		},
		"warning": {
			"warning error_rate_regression " + getOrder + " ",
			"warning map_entry_removed " + getOrder + " $.labels",
			"warning value_changed " + getOrder + " $.status",
		},
		"uncertain": nil,
		"info": {
			"info field_added " + getOrder + " $.invoice_id",
			"info map_entry_added " + getOrder + " $.labels",
			"info noise_explained " + getCatalog + " $.generated_at",
			"info noise_explained " + getCatalog + " $.request_id",
			"info noise_explained " + getOrder + " $.request_id",
			"info noise_explained " + getOrder + " $.server_time",
		},
	} {
		if got := findingKeys(&comparison, severity); !slices.Equal(got, want) {
			t.Errorf("%s findings:\n got %q\nwant %q", severity, got, want)
		}
	}

	gate := runCommand(t, nil, "replaydiff", "report", reportPath)
	if gate.code != 1 {
		t.Fatalf("report exit %d, want 1 for a regression: %s%s", gate.code, gate.stdout, gate.stderr)
	}
}
