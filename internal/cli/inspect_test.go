package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

func protoBytes(t *testing.T, set *protoset.Set, name, jsonText string) []byte {
	t.Helper()
	descriptor, err := set.MessageByURL("type.googleapis.com/" + name)
	if err != nil {
		t.Fatal(err)
	}
	m := dynamicpb.NewMessage(descriptor)
	if err := (protojson.UnmarshalOptions{Resolver: set.Types()}).Unmarshal([]byte(jsonText), m); err != nil {
		t.Fatal(err)
	}
	data, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// writeGRPCRecord stores one GetOrder call, recorded with the given descriptor digest.
func writeGRPCRecord(t *testing.T, set *protoset.Set, digest string) string {
	t.Helper()
	dir := t.TempDir()
	enc, err := traffic.NewEncoder(traffic.EncoderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	w, err := traffic.NewWriter(dir, traffic.WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stored := func(name, jsonText string) traffic.Body {
		return traffic.Body{State: traffic.BodyPresent, ContentType: "application/grpc", Data: protoBytes(t, set, name, jsonText)}
	}
	status := 0
	rec := &traffic.Record{
		SchemaVersion: traffic.SchemaVersion,
		ID:            "rec-000001",
		Seq:           1,
		CapturedAt:    time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
		Protocol:      traffic.ProtocolGRPC,
		RPC:           getOrderRPC,
		Descriptor:    &traffic.DescriptorRef{SetDigest: digest},
		Request:       traffic.Request{Method: "POST", Path: getOrderRPC, Body: stored("fixture.orders.v1.GetOrderRequest", `{"id":"ord-1"}`)},
		Response:      &traffic.Response{StatusCode: 200, GRPCStatus: &status, Body: stored("fixture.orders.v1.Order", `{"id":"ord-1","total_cents":"12"}`)},
		Outcome:       traffic.Outcome{Transport: traffic.TransportOK},
		Redaction:     traffic.Redaction{Complete: true},
	}
	frame, err := enc.Encode(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(frame); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

type inspectedGRPC struct {
	Request struct {
		Body struct {
			DataProto map[string]any `json:"data_proto"`
		} `json:"body"`
	} `json:"request"`
	Response struct {
		Body struct {
			DataProto map[string]any `json:"data_proto"`
		} `json:"body"`
	} `json:"response"`
}

func TestInspectShowsGRPCMessagesAsJSON(t *testing.T) {
	set, err := protoset.Load(fixtureDescriptors)
	if err != nil {
		t.Fatal(err)
	}
	dir := writeGRPCRecord(t, set, set.Digest())
	code, stdout, stderr := runCLI("inspect", "--traffic", dir, "--descriptor-set", fixtureDescriptors)
	if code != ExitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	var got inspectedGRPC
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if got.Request.Body.DataProto["id"] != "ord-1" || got.Response.Body.DataProto["totalCents"] != "12" {
		t.Fatalf("stdout = %s", stdout)
	}
}

// A message read with another schema could show the wrong fields, so it isn't decoded.
func TestInspectDecodesOnlyWithTheRecordedDescriptorSet(t *testing.T) {
	set, err := protoset.Load(fixtureDescriptors)
	if err != nil {
		t.Fatal(err)
	}
	dir := writeGRPCRecord(t, set, strings.Repeat("0", 32))
	code, stdout, stderr := runCLI("inspect", "--traffic", dir, "--descriptor-set", fixtureDescriptors)
	if code != ExitOK || strings.Contains(stdout, "data_proto") || !strings.Contains(stderr, "another descriptor set") {
		t.Fatalf("exit code = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}
	code, stdout, _ = runCLI("inspect", "--traffic", writeGRPCRecord(t, set, set.Digest()))
	if code != ExitOK || strings.Contains(stdout, "data_proto") {
		t.Fatalf("without a set: exit code = %d, stdout = %s", code, stdout)
	}
}
