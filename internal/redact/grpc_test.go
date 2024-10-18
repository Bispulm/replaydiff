package redact

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/Bispulm/replaydiff/internal/grpcwire"
	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

const (
	getOrder    = "/fixture.orders.v1.OrderService/GetOrder"
	watchOrders = "/fixture.orders.v1.OrderService/WatchOrders"
	protoPolicy = `
proto_fields:
  - fixture.orders.v1.Customer.email
  - fixture.orders.v1.GetOrderRequest.auth_token
  - fixture.orders.v1.Order.card_last4
  - fixture.orders.v1.Item.sku
  - fixture.orders.v1.Order.labels
  - fixture.orders.v1.Order.total_cents
  - fixture.orders.v1.Order.shipment
  - fixture.orders.v1.Order.tags
`
)

func fixtureSet(t *testing.T) *protoset.Set {
	t.Helper()
	set, err := protoset.Load("../fixture/proto/orders.binpb")
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func protoEngine(t *testing.T, policy string, set *protoset.Set) *Engine {
	t.Helper()
	p, err := ParsePolicy([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(p, Options{Descriptors: set, MaxDecompressedBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return engine
}

func messageFrom(t *testing.T, set *protoset.Set, name, jsonText string) []byte {
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

func framed(payload []byte) []byte { return grpcwire.AppendFrame(nil, payload, false) }

func storedJSON(t *testing.T, set *protoset.Set, name string, data []byte) string {
	t.Helper()
	descriptor, err := set.MessageByURL("type.googleapis.com/" + name)
	if err != nil {
		t.Fatal(err)
	}
	m := dynamicpb.NewMessage(descriptor)
	if err := proto.Unmarshal(data, m); err != nil {
		t.Fatalf("stored body isn't a valid message: %v", err)
	}
	out, err := protojson.MarshalOptions{UseProtoNames: true, Resolver: set.Types()}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestProtoFieldRulesApplyEverywhereTheMessageAppears(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	secret := sentinel(t)
	order := `{
		"id": "ord-1",
		"total_cents": "1234",
		"customer": {"id": "cus-1", "email": "` + secret + `"},
		"items": [{"sku": "` + secret + `", "qty": 2}, {"sku": "` + secret + `", "qty": 1}],
		"labels": {"region": "` + secret + `"},
		"card_last4": "` + secret + `",
		"note": "kept",
		"shipment": {"carrier": "` + secret + `"},
		"extension": {"@type": "type.googleapis.com/fixture.orders.v1.Customer", "email": "` + secret + `", "id": "inside-any"},
		"contacts": {"billing": {"id": "inside-map", "email": "` + secret + `"}},
		"tags": ["` + secret + `", "second"]
	}`
	var hits Hits
	res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: framed(messageFrom(t, set, "fixture.orders.v1.Order", order))}, &hits)
	assertAbsent(t, secret, res.BodyResult)
	if res.Failed || res.Body.State != traffic.BodyPresent || res.Body.ContentType != "application/grpc" {
		t.Fatalf("result = %+v", res.BodyResult)
	}
	got := storedJSON(t, set, "fixture.orders.v1.Order", res.Body.Data)
	assertAbsent(t, secret, got)
	for _, want := range []string{`"note":"kept"`, `"qty":2`, `"inside-any"`, `"inside-map"`, `"card_last4":"[REDACTED]"`, `"email":"[REDACTED]"`} {
		if !strings.Contains(got, want) {
			t.Errorf("stored message lacks %s:\n%s", want, got)
		}
	}
	for _, gone := range []string{`"labels"`, `"total_cents"`, `"shipment"`, `"tags"`} {
		if strings.Contains(got, gone) {
			t.Errorf("a non-text field covered by a rule must be cleared, found %s:\n%s", gone, got)
		}
	}
	rules := map[string]bool{}
	for _, hit := range hits.List() {
		rules[hit.Rule] = true
	}
	for _, rule := range []string{"fixture.orders.v1.Customer.email", "fixture.orders.v1.Item.sku", "fixture.orders.v1.Order.labels"} {
		if !rules[rule] {
			t.Errorf("no hit for %s: %+v", rule, hits.List())
		}
	}
}

func TestProtoRulesApplyToRequests(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	secret := sentinel(t)
	data := framed(messageFrom(t, set, "fixture.orders.v1.GetOrderRequest", `{"id":"ord-1","auth_token":"`+secret+`"}`))
	res := engine.GRPCBody(RequestBody, GRPCInput{RPC: getOrder, Request: true, Data: data}, &Hits{})
	assertAbsent(t, secret, res.BodyResult)
	if res.Body.State != traffic.BodyPresent || !strings.Contains(storedJSON(t, set, "fixture.orders.v1.GetOrderRequest", res.Body.Data), `"id":"ord-1"`) {
		t.Fatalf("result = %+v", res.BodyResult)
	}
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCompressedMessagesAreDecompressedThenRedacted(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	secret := sentinel(t)
	payload := gzipped(t, messageFrom(t, set, "fixture.orders.v1.Order", `{"customer":{"email":"`+secret+`"},"note":"kept"}`))
	res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Encoding: "gzip", Data: grpcwire.AppendFrame(nil, payload, true)}, &Hits{})
	assertAbsent(t, secret, res.BodyResult)
	if res.Body.State != traffic.BodyPresent || res.Body.OriginalEncoding != "gzip" {
		t.Fatalf("result = %+v", res.BodyResult)
	}
	if !strings.Contains(storedJSON(t, set, "fixture.orders.v1.Order", res.Body.Data), `"note":"kept"`) {
		t.Fatal("stored body must be the decompressed message")
	}
}

// A field the descriptor set doesn't describe has no name, so no rule can reach it. It
// could hold anything, so the body isn't stored at all.
func TestUnknownFieldsMeanTheBodyIsNotStored(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	secret := sentinel(t)
	known := messageFrom(t, set, "fixture.orders.v1.Customer", `{"id":"cus-1"}`)
	withUnknown := protowire.AppendTag(known, 99, protowire.BytesType)
	withUnknown = protowire.AppendBytes(withUnknown, []byte(secret))
	nested := messageFrom(t, set, "fixture.orders.v1.Order", `{"id":"ord-1"}`)
	nested = protowire.AppendTag(nested, 5, protowire.BytesType)
	nested = protowire.AppendBytes(nested, withUnknown)

	res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: framed(nested)}, &Hits{})
	assertAbsent(t, secret, res.BodyResult)
	if !res.Failed || res.Body.State != traffic.BodyOmitted || res.Body.Reason != ReasonProtoUnknownFields {
		t.Fatalf("result = %+v", res.BodyResult)
	}
	// The parsed message is still there for comparison, where unknown fields are compared by
	// presence only.
	if res.Message == nil {
		t.Fatal("the message is needed to compare unknown fields by presence")
	}
}

func TestAnyHoldingATypeOutsideTheSetIsNotStored(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	secret := sentinel(t)
	foreign, err := anypb.New(&anypb.Any{TypeUrl: "type.googleapis.com/elsewhere.Secret", Value: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	order := dynamicpb.NewMessage(mustMessage(t, set, "fixture.orders.v1.Order"))
	extension := order.Descriptor().Fields().ByName("extension")
	anyMessage := order.Mutable(extension).Message()
	anyMessage.Set(anyMessage.Descriptor().Fields().ByName("type_url"), protoreflect.ValueOfString("type.googleapis.com/elsewhere.Secret"))
	anyMessage.Set(anyMessage.Descriptor().Fields().ByName("value"), protoreflect.ValueOfBytes(foreign.Value))
	data, err := proto.Marshal(order)
	if err != nil {
		t.Fatal(err)
	}
	res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: framed(data)}, &Hits{})
	assertAbsent(t, secret, res.BodyResult)
	if !res.Failed || res.Body.Reason != ReasonProtoAnyUnresolved {
		t.Fatalf("result = %+v", res.BodyResult)
	}
}

func mustMessage(t *testing.T, set *protoset.Set, name string) protoreflect.MessageDescriptor {
	t.Helper()
	descriptor, err := set.MessageByURL("type.googleapis.com/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

// clobberedMapKey is an Order whose map entry repeats its key with the wrong wire type,
// which makes protobuf-go's decoder panic for a dynamic message.
func clobberedMapKey(field protowire.Number) []byte {
	entry := protowire.AppendTag(nil, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, "k")
	entry = protowire.AppendTag(entry, 1, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 0)
	order := protowire.AppendTag(nil, field, protowire.BytesType)
	return protowire.AppendBytes(order, entry)
}

func anyHolding(typeURL string, value []byte) []byte {
	anyMessage := protowire.AppendTag(nil, 1, protowire.BytesType)
	anyMessage = protowire.AppendString(anyMessage, typeURL)
	anyMessage = protowire.AppendTag(anyMessage, 2, protowire.BytesType)
	anyMessage = protowire.AppendBytes(anyMessage, value)
	order := protowire.AppendTag(nil, 17, protowire.BytesType)
	return protowire.AppendBytes(order, anyMessage)
}

func TestGRPCBodiesThatCannotBeSanitizedAreOmitted(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	secret := sentinel(t)
	valid := messageFrom(t, set, "fixture.orders.v1.Order", `{"id":"`+secret+`"}`)
	bomb := gzipped(t, bytes.Repeat([]byte{0}, 4<<20))
	orderURL := "type.googleapis.com/fixture.orders.v1.Order"
	for name, tc := range map[string]struct {
		in     GRPCInput
		reason string
	}{
		"truncated frame":       {GRPCInput{RPC: getOrder, Data: framed(valid)[:10]}, ReasonGRPCMalformedFrame},
		"two messages":          {GRPCInput{RPC: getOrder, Data: append(framed(valid), framed(valid)...)}, ReasonGRPCStreaming},
		"streaming method":      {GRPCInput{RPC: watchOrders, Data: framed(valid)}, ReasonGRPCStreaming},
		"unknown method":        {GRPCInput{RPC: "/fixture.orders.v1.OrderService/Nope", Data: framed(valid)}, ReasonProtoMethodUnknown},
		"not a message":         {GRPCInput{RPC: getOrder, Data: framed([]byte{0xff, 0xff, 0xff, 0xff, 0x0f})}, ReasonProtoMalformed},
		"map key clobbered":     {GRPCInput{RPC: getOrder, Data: framed(clobberedMapKey(7))}, ReasonProtoMalformed},
		"message map clobbered": {GRPCInput{RPC: getOrder, Data: framed(clobberedMapKey(18))}, ReasonProtoMalformed},
		"clobbered inside Any":  {GRPCInput{RPC: getOrder, Data: framed(anyHolding(orderURL, clobberedMapKey(7)))}, ReasonProtoAnyUnresolved},
		"flag without codec":    {GRPCInput{RPC: getOrder, Data: grpcwire.AppendFrame(nil, valid, true)}, ReasonGRPCMalformedFrame},
		"unsupported encoding":  {GRPCInput{RPC: getOrder, Encoding: "snappy", Data: grpcwire.AppendFrame(nil, valid, true)}, ReasonUnsupportedEncoding},
		"bad compression":       {GRPCInput{RPC: getOrder, Encoding: "gzip", Data: grpcwire.AppendFrame(nil, valid, true)}, ReasonMalformedCompression},
		"decompression bomb":    {GRPCInput{RPC: getOrder, Encoding: "gzip", Data: grpcwire.AppendFrame(nil, bomb, true)}, ReasonDecompressedTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			res := engine.GRPCBody(ResponseBody, tc.in, &Hits{})
			assertAbsent(t, secret, res.BodyResult)
			if !res.Failed || res.Body.State != traffic.BodyOmitted || res.Body.Reason != tc.reason {
				t.Fatalf("result = %+v", res.BodyResult)
			}
		})
	}
}

// nestedAny is an Order whose extension packs an Any, which packs another, depth times.
func nestedAny(depth int) []byte {
	const anyURL = "type.googleapis.com/google.protobuf.Any"
	var value []byte
	for range depth {
		anyMessage := protowire.AppendTag(nil, 1, protowire.BytesType)
		anyMessage = protowire.AppendString(anyMessage, anyURL)
		if len(value) > 0 {
			anyMessage = protowire.AppendTag(anyMessage, 2, protowire.BytesType)
			anyMessage = protowire.AppendBytes(anyMessage, value)
		}
		value = anyMessage
	}
	return protowire.AppendBytes(protowire.AppendTag(nil, 17, protowire.BytesType), value)
}

// Each Any is decoded on its own, so protobuf's own nesting limit never applies, and
// every level copied what remained. A few hundred KiB once took gigabytes.
func TestNestedAnyIsBounded(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	within := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: framed(nestedAny(protoset.MaxAnyDepth))}, &Hits{})
	if within.Body.State != traffic.BodyPresent || within.Message == nil {
		t.Fatalf("%d levels: %+v", protoset.MaxAnyDepth, within.BodyResult)
	}
	deeper := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: framed(nestedAny(protoset.MaxAnyDepth + 1))}, &Hits{})
	if !deeper.Failed || deeper.Body.Reason != ReasonProtoAnyTooDeep || deeper.Message != nil {
		t.Fatalf("%d levels: %+v, message %v", protoset.MaxAnyDepth+1, deeper.BodyResult, deeper.Message != nil)
	}

	data := framed(nestedAny(8000))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: data}, &Hits{})
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("a %d KiB message allocated %d MiB", len(data)>>10, allocated>>20)
	}
	if res.Body.Reason != ReasonProtoAnyTooDeep {
		t.Fatalf("result = %+v", res.BodyResult)
	}
}

func TestGRPCWithoutDescriptorsIsNotStored(t *testing.T) {
	engine := newEngine(t, "")
	secret := sentinel(t)
	res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: framed([]byte(secret))}, &Hits{})
	assertAbsent(t, secret, res.BodyResult)
	if !res.Failed || res.Body.Reason != ReasonProtoDescriptorMissing {
		t.Fatalf("result = %+v", res.BodyResult)
	}
}

func TestEmptyGRPCBodies(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	none := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder}, &Hits{})
	if none.Body.State != traffic.BodyEmpty || none.Body.ObservedBytes != 0 || none.Failed {
		t.Fatalf("no message = %+v", none.BodyResult)
	}
	empty := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: framed(nil)}, &Hits{})
	if empty.Body.State != traffic.BodyEmpty || empty.Body.ObservedBytes != grpcwire.HeaderSize || empty.Failed || empty.Message == nil {
		t.Fatalf("empty message = %+v", empty.BodyResult)
	}
}

func TestProtoPolicyNeedsDescriptorsAndRealFields(t *testing.T) {
	set := fixtureSet(t)
	policy, err := ParsePolicy([]byte(`proto_fields: [fixture.orders.v1.Customer.email]`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(policy, Options{}); err == nil {
		t.Error("proto_fields without a descriptor set must be refused")
	}
	// A map's entries aren't fields redaction walks, so a rule on one would match nothing.
	for _, field := range []string{"fixture.orders.v1.Customer.nope", "fixture.orders.v1.Nope.email", "fixture.orders.v1.Customer",
		"fixture.orders.v1.Order.LabelsEntry.value", "fixture.orders.v1.Order.LabelsEntry.key"} {
		policy, err := ParsePolicy([]byte(`proto_fields: ["` + field + `"]`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewEngine(policy, Options{Descriptors: set}); err == nil {
			t.Errorf("proto_fields %q must be refused: a rule that matches nothing would silently protect nothing", field)
		}
	}
	for _, field := range []string{"", "email", ".a.b"} {
		if _, err := ParsePolicy([]byte(`proto_fields: ["` + field + `"]`)); err == nil {
			t.Errorf("proto_fields %q must be refused", field)
		}
	}
}

func TestGRPCResultsEncodeWithoutTheMessage(t *testing.T) {
	set := fixtureSet(t)
	engine := protoEngine(t, protoPolicy, set)
	res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Data: framed(messageFrom(t, set, "fixture.orders.v1.Order", `{"id":"x"}`))}, &Hits{})
	if _, err := json.Marshal(res); err != nil {
		t.Fatal(err)
	}
}

func FuzzGRPCBody(f *testing.F) {
	f.Add(framed([]byte{0x0a, 0x02, 'h', 'i'}), "")
	f.Add([]byte{1, 0, 0, 0, 1, 0}, "gzip")
	f.Add([]byte{0, 0, 0, 0, 3, 0xfa, 0x06, 0x00}, "")
	set, err := protoset.Load("../fixture/proto/orders.binpb")
	if err != nil {
		f.Fatal(err)
	}
	policy, err := ParsePolicy([]byte(protoPolicy))
	if err != nil {
		f.Fatal(err)
	}
	engine, err := NewEngine(policy, Options{Descriptors: set, MaxDecompressedBytes: 1 << 20})
	if err != nil {
		f.Fatal(err)
	}
	defer engine.Close()
	f.Fuzz(func(t *testing.T, data []byte, encoding string) {
		res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: getOrder, Encoding: encoding, Data: data}, &Hits{})
		switch res.Body.State {
		case traffic.BodyPresent:
			if res.Failed {
				t.Fatal("failed result holds data")
			}
			descriptor, err := set.MessageByURL("type.googleapis.com/fixture.orders.v1.Order")
			if err != nil {
				t.Fatal(err)
			}
			stored := dynamicpb.NewMessage(descriptor)
			if err := proto.Unmarshal(res.Body.Data, stored); err != nil {
				t.Fatalf("stored body isn't a valid message: %v", err)
			}
			if len(stored.GetUnknown()) != 0 {
				t.Fatal("stored body has unknown fields")
			}
		case traffic.BodyEmpty, traffic.BodyOmitted:
			if len(res.Body.Data) != 0 {
				t.Fatalf("state %s holds data", res.Body.State)
			}
		case traffic.BodyTruncated, traffic.BodyUnavailable:
			t.Fatalf("unexpected state %s", res.Body.State)
		}
	})
}
