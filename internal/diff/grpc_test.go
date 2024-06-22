package diff

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/Bispulm/replaydiff/internal/fixture"
	"github.com/Bispulm/replaydiff/internal/grpcwire"
	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/replay"
)

const getOrderRPC = "/fixture.orders.v1.OrderService/GetOrder"

func orderDescriptors(t testing.TB) *protoset.Set {
	t.Helper()
	set, err := protoset.Parse(fixture.DescriptorSet())
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func grpcComparator(t *testing.T, config, policy string, set *protoset.Set) *Comparator {
	t.Helper()
	cfg, err := ParseConfig([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	p, err := redact.ParsePolicy([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redact.NewEngine(p, redact.Options{Descriptors: set})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	comparator, err := New(cfg, engine)
	if err != nil {
		t.Fatal(err)
	}
	return comparator
}

type grpcReply struct {
	status  int
	message []byte
	frames  []byte
	noFrame bool
}

func orderBytes(t testing.TB, set *protoset.Set, jsonText string) []byte {
	t.Helper()
	descriptor, err := set.MessageByURL("type.googleapis.com/fixture.orders.v1.Order")
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

func okOrderMessage(t testing.TB, set *protoset.Set, jsonText string) *dynamicpb.Message {
	t.Helper()
	descriptor, err := set.MessageByURL("type.googleapis.com/fixture.orders.v1.Order")
	if err != nil {
		t.Fatal(err)
	}
	m := dynamicpb.NewMessage(descriptor)
	if err := (protojson.UnmarshalOptions{Resolver: set.Types()}).Unmarshal([]byte(jsonText), m); err != nil {
		t.Fatal(err)
	}
	return m
}

func okOrder(t *testing.T, set *protoset.Set, jsonText string) grpcReply {
	t.Helper()
	return grpcReply{status: 0, message: orderBytes(t, set, jsonText)}
}

func grpcError(code int) grpcReply { return grpcReply{status: code, noFrame: true} }

func grpcRecord(seq int, a, b, c grpcReply) *replay.RecordResult {
	result := &replay.RecordResult{ID: "rec-" + strconv.Itoa(seq), Seq: uint64(seq), Method: http.MethodPost, Path: getOrderRPC, RPC: getOrderRPC}
	for i, r := range []grpcReply{a, b, c} {
		body := r.frames
		if body == nil && !r.noFrame {
			body = grpcwire.AppendFrame(nil, r.message, false)
		}
		call := replay.CallResult{
			Role:    replay.Role(i).String(),
			Outcome: replay.CallOK,
			Status:  http.StatusOK,
			Header:  http.Header{"Content-Type": {"application/grpc"}},
			Body:    body,
		}
		if r.status >= 0 {
			code := r.status
			call.GRPCStatus = &code
		}
		result.Calls[i] = call
	}
	return result
}

func compareGRPC(t *testing.T, a, b, c grpcReply) *Result {
	t.Helper()
	comparator := grpcComparator(t, "", "", orderDescriptors(t))
	comparator.Observe(grpcRecord(1, a, b, c))
	return comparator.Result()
}

func TestIdenticalGRPCResponsesProduceNoFindings(t *testing.T) {
	set := orderDescriptors(t)
	same := okOrder(t, set, `{"id":"ord-1","customer":{"tier":"gold"},"labels":{"a":"b"},"items":[{"sku":"s"}],"note":"n","checksum":"AQI="}`)
	wantKinds(t, compareGRPC(t, same, same, same))
}

func TestGRPCStatusChanges(t *testing.T) {
	set := orderDescriptors(t)
	ok := okOrder(t, set, `{"id":"ord-1"}`)
	const notFound, permissionDenied, internal, unavailable = 5, 7, 13, 14
	for name, tc := range map[string]struct {
		a, b, c grpcReply
		want    []string
	}{
		"ok to internal":           {ok, ok, grpcError(internal), []string{"breaking:grpc_error_introduced:"}},
		"ok to not found":          {ok, ok, grpcError(notFound), []string{"breaking:grpc_error_introduced:"}},
		"not found to internal":    {grpcError(notFound), grpcError(notFound), grpcError(internal), []string{"breaking:grpc_error_introduced:"}},
		"not found to unavailable": {grpcError(notFound), grpcError(notFound), grpcError(unavailable), []string{"breaking:grpc_error_introduced:"}},
		"not found to ok":          {grpcError(notFound), grpcError(notFound), ok, []string{"warning:grpc_status_changed:"}},
		"not found to denied":      {grpcError(notFound), grpcError(notFound), grpcError(permissionDenied), []string{"warning:grpc_status_changed:"}},
		"internal to unavailable":  {grpcError(internal), grpcError(internal), grpcError(unavailable), []string{"warning:grpc_status_changed:"}},
		"same error":               {grpcError(notFound), grpcError(notFound), grpcError(notFound), nil},
		"baselines disagree":       {ok, grpcError(notFound), ok, []string{"uncertain:baseline_status_unstable:"}},
		"fault outside both":       {ok, grpcError(notFound), grpcError(internal), []string{"uncertain:baseline_status_unstable:", "breaking:grpc_error_introduced:"}},
		"status missing":           {ok, ok, grpcReply{status: -1, message: ok.message}, []string{"breaking:grpc_error_introduced:"}},
		"error to status missing":  {grpcError(notFound), grpcError(notFound), grpcReply{status: -1, noFrame: true}, []string{"breaking:grpc_error_introduced:"}},
		// A client discards any message that comes with an error, so it isn't compared.
		"same error, other message": {grpcReply{status: notFound, message: ok.message}, grpcReply{status: notFound, message: ok.message}, grpcReply{status: notFound, message: okOrder(t, set, `{"id":"other"}`).message}, nil},
		// An OK reply must carry a message, and grpc-go fails the call when it doesn't.
		"ok without a message": {ok, ok, grpcReply{status: 0, noFrame: true}, []string{"breaking:body_removed:"}},
	} {
		t.Run(name, func(t *testing.T) {
			wantKinds(t, compareGRPC(t, tc.a, tc.b, tc.c), tc.want...)
		})
	}
}

// Protobuf can't tell an unset ordinary field from one set to its default, so those are
// value changes. Fields with presence (messages, optional fields, oneof members) can be
// removed, and that is breaking.
func TestProtobufPresenceRules(t *testing.T) {
	set := orderDescriptors(t)
	for name, tc := range map[string]struct {
		base, candidate string
		want            []string
	}{
		"optional field unset":  {`{"note":"n"}`, `{}`, []string{"breaking:field_removed:$.note"}},
		"optional set to empty": {`{"note":"n"}`, `{"note":""}`, []string{"warning:value_changed:$.note"}},
		"message field unset":   {`{"shipment":{"carrier":"c"}}`, `{}`, []string{"breaking:field_removed:$.shipment"}},
		"message field added":   {`{}`, `{"shipment":{}}`, []string{"info:field_added:$.shipment"}},
		"oneof member switched": {`{"card_last4":"4242"}`, `{"invoice_id":"i"}`, []string{"breaking:field_removed:$.card_last4", "info:field_added:$.invoice_id"}},
		"implicit to default":   {`{"customer":{"tier":"gold"}}`, `{"customer":{}}`, []string{"warning:value_changed:$.customer.tier"}},
		"implicit number":       {`{"weight":1.5}`, `{}`, []string{"warning:value_changed:$.weight"}},
		"enum changed":          {`{"status":"ORDER_STATUS_SHIPPED"}`, `{"status":"ORDER_STATUS_PENDING"}`, []string{"warning:value_changed:$.status"}},
		"enum number unknown":   {`{"status":"ORDER_STATUS_SHIPPED"}`, `{"status":7}`, []string{"warning:value_changed:$.status"}},
		"enum unknown numbers":  {`{"status":7}`, `{"status":8}`, []string{"warning:value_changed:$.status"}},
		"double not finite":     {`{"weight":"NaN"}`, `{"weight":1.5}`, []string{"warning:value_changed:$.weight"}},
		"int64 precision":       {`{"total_cents":"9007199254740993"}`, `{"total_cents":"9007199254740992"}`, []string{"warning:value_changed:$.total_cents"}},
		"bytes changed":         {`{"checksum":"AQI="}`, `{"checksum":"AQM="}`, []string{"warning:value_changed:$.checksum"}},
		"repeated shorter":      {`{"items":[{"sku":"a"},{"sku":"b"}]}`, `{"items":[{"sku":"a"}]}`, []string{"warning:array_length_changed:$.items"}},
		"repeated emptied":      {`{"tags":["a"]}`, `{}`, []string{"warning:array_length_changed:$.tags"}},
		"repeated order":        {`{"tags":["a","b"]}`, `{"tags":["b","a"]}`, []string{"warning:value_changed:$.tags[*]"}},
		"map entry removed":     {`{"labels":{"region":"us","channel":"web"}}`, `{"labels":{"channel":"web"}}`, []string{"warning:map_entry_removed:$.labels"}},
		"map entry added":       {`{"labels":{"channel":"web"}}`, `{"labels":{"channel":"web","experiment":"b"}}`, []string{"info:map_entry_added:$.labels"}},
		"map value changed":     {`{"labels":{"channel":"web"}}`, `{"labels":{"channel":"app"}}`, []string{"warning:value_changed:$.labels[*]"}},
		"map message field":     {`{"contacts":{"x":{"tier":"gold"}}}`, `{"contacts":{"x":{"tier":"silver"}}}`, []string{"warning:value_changed:$.contacts[*].tier"}},
		"any resolved":          {`{"extension":{"@type":"type.googleapis.com/fixture.orders.v1.Customer","tier":"gold"}}`, `{"extension":{"@type":"type.googleapis.com/fixture.orders.v1.Customer","tier":"silver"}}`, []string{"warning:value_changed:$.extension.tier"}},
		"any type changed":      {`{"extension":{"@type":"type.googleapis.com/fixture.orders.v1.Customer"}}`, `{"extension":{"@type":"type.googleapis.com/fixture.orders.v1.Item"}}`, []string{"breaking:type_changed:$.extension"}},
	} {
		t.Run(name, func(t *testing.T) {
			base, candidate := okOrder(t, set, tc.base), okOrder(t, set, tc.candidate)
			wantKinds(t, compareGRPC(t, base, base, candidate), tc.want...)
		})
	}
}

func TestIdenticalNonFiniteNumbersAreEqual(t *testing.T) {
	set := orderDescriptors(t)
	for _, weight := range []string{`"NaN"`, `"Infinity"`, `"-Infinity"`} {
		same := okOrder(t, set, `{"weight":`+weight+`}`)
		wantKinds(t, compareGRPC(t, same, same, same))
	}
}

func TestMapEntriesTheBaselinesDisagreeOnAreUncertain(t *testing.T) {
	set := orderDescriptors(t)
	with, without := okOrder(t, set, `{"labels":{"region":"us"}}`), okOrder(t, set, `{}`)
	wantKinds(t, compareGRPC(t, with, without, without), "uncertain:baseline_presence_unstable:$.labels[*]")
}

func TestProtobufEvidenceNamesTheType(t *testing.T) {
	set := orderDescriptors(t)
	for _, tc := range []struct{ base, candidate, typ, text string }{
		{`{"status":"ORDER_STATUS_SHIPPED"}`, `{"status":"ORDER_STATUS_PENDING"}`, "enum", "ORDER_STATUS_PENDING"},
		{`{"status":"ORDER_STATUS_SHIPPED"}`, `{"status":7}`, "enum", "7"},
		{`{"checksum":"AQI="}`, `{"checksum":"AQM="}`, "bytes", `"AQM="`},
	} {
		comparator := grpcComparator(t, "evidence: values", "", set)
		comparator.Observe(grpcRecord(1, okOrder(t, set, tc.base), okOrder(t, set, tc.base), okOrder(t, set, tc.candidate)))
		result := comparator.Result()
		if len(result.Findings) != 1 {
			t.Fatalf("findings = %v", kinds(result))
		}
		got := result.Findings[0].Evidence.Candidate
		if got.Type != tc.typ || got.Text != tc.text {
			t.Errorf("candidate evidence = %+v, want type %q and text %q", got, tc.typ, tc.text)
		}
	}
}

func withUnknownField(message []byte, number protowire.Number, value []byte) []byte {
	message = protowire.AppendTag(message, number, protowire.BytesType)
	return protowire.AppendBytes(message, value)
}

// A field the schema doesn't describe can't be redacted, so its value is never kept. Its
// presence is still compared, which is what shows a candidate added or dropped one.
func TestUnknownFieldsAreComparedByPresenceOnly(t *testing.T) {
	set := orderDescriptors(t)
	const secret = "rdsentinel-unknown-field-value"
	base := okOrder(t, set, `{"id":"ord-1"}`)
	added := grpcReply{message: withUnknownField(base.message, 99, []byte(secret))}
	result := compareGRPC(t, base, base, added)
	wantKinds(t, result, "info:field_added:$['#99']")
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("an unknown field's value reached the result: %s", data)
	}

	result = compareGRPC(t, added, added, base)
	wantKinds(t, result, "breaking:field_removed:$['#99']")

	changed := grpcReply{message: withUnknownField(base.message, 99, []byte("different"))}
	wantKinds(t, compareGRPC(t, added, added, changed))
}

func TestAnyOfAnUnknownTypeIsComparedWithoutRevealingIt(t *testing.T) {
	set := orderDescriptors(t)
	const secret = "rdsentinel-inside-foreign-any"
	foreign := func(value string) grpcReply {
		order := orderBytes(t, set, `{"id":"ord-1"}`)
		anyMessage := protowire.AppendTag(nil, 1, protowire.BytesType)
		anyMessage = protowire.AppendString(anyMessage, "type.googleapis.com/elsewhere.Secret")
		anyMessage = protowire.AppendTag(anyMessage, 2, protowire.BytesType)
		anyMessage = protowire.AppendBytes(anyMessage, []byte(value))
		order = protowire.AppendTag(order, 17, protowire.BytesType)
		return grpcReply{message: protowire.AppendBytes(order, anyMessage)}
	}
	result := compareGRPC(t, foreign(secret+"-a"), foreign(secret+"-a"), foreign(secret+"-b"))
	wantKinds(t, result, "warning:value_changed:$.extension.value")
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("an unresolved Any's value reached the result: %s", data)
	}
}

func TestGRPCBodiesThatCannotBeInterpreted(t *testing.T) {
	set := orderDescriptors(t)
	ok := okOrder(t, set, `{"id":"ord-1"}`)
	malformed := grpcReply{frames: []byte{0, 0, 0, 0, 9, 1}}
	two := grpcReply{frames: append(grpcwire.AppendFrame(nil, ok.message, false), grpcwire.AppendFrame(nil, ok.message, false)...)}
	wantKinds(t, compareGRPC(t, ok, ok, malformed), "breaking:body_invalid:")
	wantKinds(t, compareGRPC(t, ok, ok, two), "breaking:body_invalid:")
	wantKinds(t, compareGRPC(t, malformed, malformed, malformed), "uncertain:body_not_compared:")

	comparator := grpcComparator(t, "", "", nil)
	comparator.Observe(grpcRecord(1, ok, ok, okOrder(t, set, `{"id":"other"}`)))
	wantKinds(t, comparator.Result(), "uncertain:body_not_compared:")
}

func TestGRPCRoutesUseTheMethodName(t *testing.T) {
	set := orderDescriptors(t)
	ok := okOrder(t, set, `{"id":"ord-1"}`)
	result := compareGRPC(t, ok, ok, grpcError(13))
	if got := result.Findings[0].Route; got != "POST "+getOrderRPC {
		t.Fatalf("route = %q; a version in a package name isn't an ID", got)
	}
}

func TestGRPCNoiseIsExplainedAndRedactionApplies(t *testing.T) {
	set := orderDescriptors(t)
	const secret = "rdsentinel-proto-email"
	comparator := grpcComparator(t, "", `proto_fields: [fixture.orders.v1.Customer.email]`, set)
	for i := range 3 {
		order := func(v int) grpcReply {
			return okOrder(t, set, `{"id":"ord-1","server_time":"t`+strconv.Itoa(i*10+v)+`","customer":{"email":"`+secret+strconv.Itoa(v)+`"}}`)
		}
		comparator.Observe(grpcRecord(i+1, order(1), order(2), order(3)))
	}
	result := comparator.Result()
	wantKinds(t, result, "info:noise_explained:$.server_time")
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("a covered value reached the result: %s", data)
	}
}

func TestStructuralChangesOnNoisyProtoFieldsAreBreaking(t *testing.T) {
	set := orderDescriptors(t)
	comparator := grpcComparator(t, "", "", set)
	for i := range 5 {
		note := func(v int) string { return `{"note":"n` + strconv.Itoa(i*10+v) + `"}` }
		comparator.Observe(grpcRecord(i+1, okOrder(t, set, note(1)), okOrder(t, set, note(2)), okOrder(t, set, `{}`)))
	}
	keys := kinds(comparator.Result())
	found := false
	for _, k := range keys {
		found = found || k == "breaking:field_removed:$.note"
	}
	if !found {
		t.Fatalf("findings = %v", keys)
	}
}

func FuzzGRPCCompare(f *testing.F) {
	set := orderDescriptors(f)
	order := orderBytes(f, set, `{"id":"o","labels":{"k":"v"},"contacts":{"x":{"tier":"gold"}},"weight":"NaN","extension":{"@type":"type.googleapis.com/fixture.orders.v1.Customer","tier":"t"}}`)
	f.Add(order, order, withUnknownField(order, 99, []byte("x")), 0, 0, 0)
	f.Add(order, []byte{0xff}, []byte{}, 0, 5, 13)
	f.Add([]byte{0x8a, 0x01, 0x02, 0x0a, 0x00}, order, order, 0, 0, -1)

	f.Fuzz(func(t *testing.T, a, b, c []byte, sa, sb, sc int) {
		reply := func(message []byte, status int) grpcReply {
			return grpcReply{status: max(min(status, 16), -1), message: message}
		}
		comparator := grpcComparator(t, "evidence: values", "", set)
		comparator.Observe(grpcRecord(1, reply(a, sa), reply(b, sb), reply(c, sc)))
		if _, err := json.Marshal(comparator.Result()); err != nil {
			t.Fatalf("result doesn't encode: %v", err)
		}

		same := grpcComparator(t, "evidence: values", "", set)
		same.Observe(grpcRecord(1, reply(a, sa), reply(a, sa), reply(a, sa)))
		for _, finding := range same.Result().Findings {
			if finding.Severity == SeverityBreaking || finding.Severity == SeverityWarning {
				t.Fatalf("identical responses reported as a change: %+v", finding)
			}
		}
	})
}

// gRPC reports failure in its status, over HTTP 200, so the error rate counts server
// faults and a missing status. A client error such as not_found isn't a failure.
func TestGRPCServerFaultsCountTowardTheErrorRate(t *testing.T) {
	set := orderDescriptors(t)
	ok := okOrder(t, set, `{"id":"ord-1"}`)
	for name, tc := range map[string]struct {
		candidate grpcReply
		http      int
		want      bool
	}{
		"internal":       {grpcError(13), http.StatusOK, true},
		"unavailable":    {grpcError(14), http.StatusOK, true},
		"status missing": {grpcReply{status: -1, noFrame: true}, http.StatusOK, true},
		"not found":      {grpcError(5), http.StatusOK, false},
		// A proxy in front can fail the call whatever status it passes along.
		"http failure": {ok, http.StatusBadGateway, true},
	} {
		t.Run(name, func(t *testing.T) {
			comparator := grpcComparator(t, "", "", set)
			for i := range 100 {
				candidate := ok
				if i < 5 {
					candidate = tc.candidate
				}
				record := grpcRecord(i+1, ok, ok, candidate)
				if i < 5 {
					record.Calls[2].Status = tc.http
				}
				comparator.Observe(record)
			}
			result := comparator.Result()
			got := slices.ContainsFunc(result.Findings, func(f Finding) bool { return f.Kind == KindErrorRateRegression })
			if got != tc.want {
				t.Fatalf("error_rate_regression reported = %v, want %v: %v", got, tc.want, kinds(result))
			}
		})
	}
}

// Comparison unpacks no more levels of Any than redaction sanitized. Deeper ones are
// compared by digest, so their bytes are never decoded or shown.
func TestAnyPackingAnyIsUnpacked(t *testing.T) {
	set := orderDescriptors(t)
	nested := func(tier string) grpcReply {
		return okOrder(t, set, `{"extension":{"@type":"type.googleapis.com/google.protobuf.Any","value":{"@type":"type.googleapis.com/fixture.orders.v1.Customer","tier":"`+tier+`"}}}`)
	}
	wantKinds(t, compareGRPC(t, nested("gold"), nested("gold"), nested("silver")), "warning:value_changed:$.extension.value.tier")
}

func TestNestedAnyIsComparedOnlyAsDeepAsRedactionGoes(t *testing.T) {
	set := orderDescriptors(t)
	anyDescriptor, err := set.MessageByURL("type.googleapis.com/google.protobuf.Any")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "rdsentinel-below-the-limit"
	inner, err := proto.Marshal(okOrderMessage(t, set, `{"note":"`+secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	typeURL := "type.googleapis.com/fixture.orders.v1.Order"
	for range protoset.MaxAnyDepth + 1 {
		packed := dynamicpb.NewMessage(anyDescriptor)
		packed.Set(anyDescriptor.Fields().ByName("type_url"), protoreflect.ValueOfString(typeURL))
		packed.Set(anyDescriptor.Fields().ByName("value"), protoreflect.ValueOfBytes(inner))
		if inner, err = proto.Marshal(packed); err != nil {
			t.Fatal(err)
		}
		typeURL = "type.googleapis.com/google.protobuf.Any"
	}
	outer := dynamicpb.NewMessage(anyDescriptor)
	if err := proto.Unmarshal(inner, outer); err != nil {
		t.Fatal(err)
	}
	tree := anyTree(outer, set, 0)
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || !strings.Contains(string(data), "digest") {
		t.Fatalf("tree = %s", data)
	}
}

func orderWithForeignAny(typeURL string) grpcReply {
	anyMessage := protowire.AppendTag(nil, 1, protowire.BytesType)
	anyMessage = protowire.AppendString(anyMessage, typeURL)
	anyMessage = protowire.AppendTag(anyMessage, 2, protowire.BytesType)
	anyMessage = protowire.AppendBytes(anyMessage, []byte{8, 1})
	return grpcReply{message: protowire.AppendBytes(protowire.AppendTag(nil, 17, protowire.BytesType), anyMessage)}
}

// An Any's type URL is the sender's text and acts as a type name, which evidence limits
// didn't cover. A long one is cut, and a digest still tells two of them apart.
func TestLongAnyTypeURLsAreBounded(t *testing.T) {
	long := "example.test/acct.Secret?k=" + strings.Repeat("S", 600)
	result := compareGRPC(t, orderWithForeignAny(long+"a"), orderWithForeignAny(long+"a"), orderWithForeignAny(long+"b"))
	wantKinds(t, result, "breaking:type_changed:$.extension")
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), strings.Repeat("S", 200)) {
		t.Fatalf("the type URL reached the result in full: %d bytes", len(data))
	}
}
