package diff

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/Bispulm/replaydiff/internal/grpcwire"
	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/replay"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// Values in a tree built from a protobuf message, where they need different comparison
// from their JSON counterparts. Fields are exported so that they encode for evidence.
type (
	// protoMap is a map field. Its entries are data, so a missing key is a changed value
	// rather than a removed field.
	protoMap map[string]any
	// protoEnum compares by number, so a renamed value isn't a change.
	protoEnum struct {
		Number int32  `json:"number"`
		Name   string `json:"name,omitempty"`
	}
	// protoBytes is a bytes field, base64 encoded.
	protoBytes string
	// unknownField is a field the schema doesn't describe. Only its wire type is kept,
	// because its value couldn't have been sanitized.
	unknownField struct {
		Wire string `json:"wire"`
	}
	// opaqueValue is content that can't be interpreted, compared by digest and never shown.
	opaqueValue struct {
		Digest string `json:"digest"`
	}
	// anyValue is a google.protobuf.Any, whose packed type acts as its type.
	anyValue struct {
		TypeURL string         `json:"type_url"`
		Tree    map[string]any `json:"tree"`
	}
)

func (e protoEnum) label() string {
	if e.Name != "" {
		return e.Name
	}
	return strconv.Itoa(int(e.Number))
}

// grpcView sanitizes a gRPC response with the descriptor set and turns its message into
// a tree the walker compares.
func (r *recordCompare) grpcView(call *replay.CallResult) bodyView {
	var discard redact.Hits
	result := r.c.engine.GRPCBody(redact.ResponseBody, redact.GRPCInput{
		RPC:      r.result.RPC,
		Encoding: call.Header.Get("Grpc-Encoding"),
		Data:     call.Body,
	}, &discard)
	switch {
	case result.Message != nil:
		return bodyView{kind: viewJSON, tree: protoTree(result.Message, r.c.engine.Descriptors(), 0)}
	case result.Body.State == traffic.BodyEmpty:
		return bodyView{kind: viewEmpty}
	default:
		// This includes a missing descriptor, which affects every call alike, so the
		// record is reported as not compared rather than as a broken candidate.
		return bodyView{kind: viewOmitted, failed: true}
	}
}

// compareGRPCStatus compares gRPC status and reports whether bodies should be compared.
// A status the candidate introduces that neither baseline shows is a regression when it's
// an error where there was none, or a server fault where there was an answer.
func (r *recordCompare) compareGRPCStatus(a, b, candidate *replay.CallResult) bool {
	sa, sb, sc := grpcCode(a), grpcCode(b), grpcCode(candidate)
	value := func(code int) Value {
		if code < 0 {
			return Value{Present: false, Type: "grpc_status"}
		}
		return Value{Present: true, Type: "grpc_status", Text: grpcwire.StatusName(code)}
	}
	evidence := func() *Evidence { return r.evidence("grpc-status", value(sa), value(sb), value(sc)) }
	overall := r.field("")
	fault := grpcFault

	if sa != sb {
		overall.note(KindBaselineStatusUnstable, evidence())
		if sc != sa && sc != sb && fault(sc) {
			overall.note(KindGRPCErrorIntroduced, evidence())
		}
		return false
	}
	if sc != sa {
		if (sa == 0 && sc != 0) || (fault(sc) && !fault(sa)) {
			overall.note(KindGRPCErrorIntroduced, evidence())
		} else {
			overall.note(KindGRPCStatusChanged, evidence())
		}
		return false
	}
	// The same error on all three: there's no message to compare.
	return sa == 0
}

// grpcCode returns a call's gRPC status, or -1 if it has none.
func grpcCode(call *replay.CallResult) int {
	if call.GRPCStatus == nil {
		return -1
	}
	return *call.GRPCStatus
}

// grpcFault reports a status that blames the server. A call that ends without a status
// has failed in transit, which counts the same.
func grpcFault(code int) bool { return code < 0 || grpcwire.IsServerFault(code) }

// protoTree turns a message into the tree the walker compares, following protobuf's own
// presence rules. A field with presence (a message, an optional field or a oneof member)
// appears only when set, so it can be removed. An ordinary scalar always appears, holding
// its default when unset, because the wire format can't tell those apart. Lists and maps
// always appear, since empty and absent are the same.
func protoTree(message protoreflect.Message, set *protoset.Set, anyDepth int) map[string]any {
	out := make(map[string]any)
	fields := message.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		name := string(field.Name())
		switch {
		case field.IsMap():
			entries := protoMap{}
			message.Get(field).Map().Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
				entries[key.String()] = protoValue(field.MapValue(), value, set, anyDepth)
				return true
			})
			out[name] = entries
		case field.IsList():
			list := message.Get(field).List()
			items := make([]any, list.Len())
			for j := range list.Len() {
				items[j] = protoValue(field, list.Get(j), set, anyDepth)
			}
			out[name] = items
		case field.HasPresence():
			if message.Has(field) {
				out[name] = protoValue(field, message.Get(field), set, anyDepth)
			}
		default:
			out[name] = protoValue(field, message.Get(field), set, anyDepth)
		}
	}
	for number, wire := range unknownFields(message.GetUnknown()) {
		out["#"+strconv.Itoa(int(number))] = unknownField{Wire: wire}
	}
	return out
}

func protoValue(field protoreflect.FieldDescriptor, value protoreflect.Value, set *protoset.Set, anyDepth int) any {
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		if field.Message().FullName() == anyName {
			return anyTree(value.Message(), set, anyDepth)
		}
		return protoTree(value.Message(), set, anyDepth)
	case protoreflect.EnumKind:
		number := value.Enum()
		enum := protoEnum{Number: int32(number)}
		if described := field.Enum().Values().ByNumber(number); described != nil {
			enum.Name = string(described.Name())
		}
		return enum
	case protoreflect.BoolKind:
		return value.Bool()
	case protoreflect.StringKind:
		return value.String()
	case protoreflect.BytesKind:
		return protoBytes(base64.StdEncoding.EncodeToString(value.Bytes()))
	case protoreflect.FloatKind:
		return json.Number(strconv.FormatFloat(value.Float(), 'g', -1, 32))
	case protoreflect.DoubleKind:
		return json.Number(strconv.FormatFloat(value.Float(), 'g', -1, 64))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind, protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return json.Number(strconv.FormatUint(value.Uint(), 10))
	default:
		// Every remaining kind is a signed integer, kept exact as text.
		return json.Number(strconv.FormatInt(value.Int(), 10))
	}
}

const anyName = "google.protobuf.Any"

// anyTree unpacks an Any whose type the set describes, to the depth redaction sanitizes.
// Any other type, or a deeper level, stays opaque: its bytes weren't sanitized, so only a
// digest of them is kept.
func anyTree(message protoreflect.Message, set *protoset.Set, anyDepth int) anyValue {
	fields := message.Descriptor().Fields()
	typeURL := message.Get(fields.ByName("type_url")).String()
	value := message.Get(fields.ByName("value")).Bytes()
	result := anyValue{TypeURL: typeURL, Tree: map[string]any{}}
	if typeURL == "" && len(value) == 0 {
		return result
	}
	if descriptor, err := set.MessageByURL(typeURL); err == nil && anyDepth < protoset.MaxAnyDepth {
		inner := dynamicpb.NewMessage(descriptor)
		if protoset.Unmarshal(value, inner) == nil {
			if descriptor.FullName() == anyName {
				// An Any packing another is unpacked in turn, under the field that holds it.
				result.Tree = map[string]any{"value": anyTree(inner, set, anyDepth+1)}
			} else {
				result.Tree = protoTree(inner, set, anyDepth+1)
			}
			return result
		}
	}
	sum := sha256.Sum256(value)
	result.Tree["value"] = opaqueValue{Digest: hex.EncodeToString(sum[:8])}
	return result
}

var wireNames = map[protowire.Type]string{
	protowire.VarintType:     "varint",
	protowire.Fixed32Type:    "fixed32",
	protowire.Fixed64Type:    "fixed64",
	protowire.BytesType:      "bytes",
	protowire.StartGroupType: "group",
}

// unknownFields lists the field numbers and wire types in unknown bytes, and nothing
// else. Malformed bytes end the listing, since a parser accepted them only as opaque.
func unknownFields(raw []byte) map[protowire.Number]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[protowire.Number]string)
	for len(raw) > 0 {
		number, wire, n := protowire.ConsumeTag(raw)
		if n < 0 {
			break
		}
		m := protowire.ConsumeFieldValue(number, wire, raw[n:])
		if m < 0 {
			break
		}
		if _, seen := out[number]; !seen {
			out[number] = wireNames[wire]
		}
		raw = raw[n+m:]
	}
	return out
}

// compareProtoMaps compares map fields by key. Entries are data, so a missing key is a
// changed value, not a removed field. The path normalizes keys to [*], because they vary.
func (r *recordCompare) compareProtoMaps(path, concrete string, depth int, a, b, c protoMap) {
	keys := make([]string, 0, len(a))
	for _, m := range []protoMap{a, b, c} {
		for key := range m {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	entryPath := path + "[*]"
	for _, key := range keys {
		va, pa := a[key]
		vb, pb := b[key]
		vc, pc := c[key]
		entry := concrete + "[" + strconv.Quote(boundedKey(key)) + "]"
		evidence := func() *Evidence { return r.nodeEvidence(entry, va, vb, vc, pa, pb, pc) }
		switch {
		case !pa && !pb:
			if pc {
				r.field(path).note(KindMapEntryAdded, evidence())
			}
		case pa != pb:
			r.field(entryPath).note(KindBaselinePresenceUnstable, evidence())
		case !pc:
			r.field(path).note(KindMapEntryRemoved, evidence())
		default:
			r.compareNode(entryPath, entry, depth+1, va, vb, vc, true, true, true)
		}
	}
}

func boundedKey(key string) string {
	if len(key) <= maxKeyBytes {
		return key
	}
	limit := maxKeyBytes
	for limit > 0 && key[limit]&0xC0 == 0x80 {
		limit--
	}
	return key[:limit] + "..."
}
