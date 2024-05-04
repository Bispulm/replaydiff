package redact

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/Bispulm/replaydiff/internal/grpcwire"
	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// Reasons a gRPC body wasn't stored.
const (
	ReasonProtoDescriptorMissing = "proto_descriptor_missing"
	ReasonProtoMethodUnknown     = "proto_method_unknown"
	ReasonGRPCStreaming          = "grpc_streaming"
	ReasonGRPCMalformedFrame     = "grpc_malformed_frame"
	ReasonProtoMalformed         = "proto_malformed"
	ReasonProtoUnknownFields     = "proto_unknown_fields"
	ReasonProtoAnyUnresolved     = "proto_any_unresolved"
)

// grpcContentType is how stored gRPC bodies are labeled. They hold one message, with
// its length prefix removed and decompressed.
const grpcContentType = "application/grpc"

// GRPCInput is a complete gRPC body as observed: the length-prefixed messages of one
// direction of a call.
type GRPCInput struct {
	// RPC is the method path, such as /package.Service/Method.
	RPC string
	// Request selects the method's input type. Otherwise its output type is used.
	Request bool
	// Encoding is the grpc-encoding header, which applies to compressed messages.
	Encoding string
	Data     []byte
}

// GRPCResult is a sanitized gRPC body.
type GRPCResult struct {
	BodyResult
	// Message is the sanitized message, for comparison only. Unknown fields are still in
	// it, because comparison checks their presence, and so it must never be stored. It is
	// nil if the body couldn't be parsed.
	Message protoreflect.Message `json:"-"`
}

// protoWalk notes what sanitizing found that makes a message unsafe to store.
type protoWalk struct {
	unknown       bool
	anyUnresolved bool
}

// GRPCBody sanitizes a unary call's body with the descriptor set. As with other bodies,
// anything that can't be sanitized is omitted, never stored as it was. That includes a
// message holding fields the set doesn't describe: no rule can name them, so they could
// hold anything.
func (e *Engine) GRPCBody(location Location, in GRPCInput, hits *Hits) GRPCResult {
	body := traffic.Body{ContentType: grpcContentType, ObservedBytes: int64(len(in.Data))}
	result := GRPCResult{}
	omit := func(reason string) GRPCResult {
		body.State = traffic.BodyOmitted
		body.Reason = reason
		result.BodyResult = BodyResult{Body: body, Failed: true}
		return result
	}
	if e.descriptors == nil {
		return omit(ReasonProtoDescriptorMissing)
	}
	method, err := e.descriptors.Method(in.RPC)
	if err != nil {
		return omit(ReasonProtoMethodUnknown)
	}
	if protoset.IsStreaming(method) {
		return omit(ReasonGRPCStreaming)
	}
	frames, err := grpcwire.ParseFrames(in.Data)
	switch {
	case err != nil:
		return omit(ReasonGRPCMalformedFrame)
	case len(frames) == 0:
		body.State = traffic.BodyEmpty
		result.BodyResult = BodyResult{Body: body}
		return result
	case len(frames) > 1:
		return omit(ReasonGRPCStreaming)
	}

	payload := frames[0].Payload
	if frames[0].Compressed {
		encoding := strings.ToLower(strings.TrimSpace(in.Encoding))
		if encoding == "" || encoding == "identity" {
			return omit(ReasonGRPCMalformedFrame)
		}
		decoded, reason := e.decompress(encoding, payload)
		if reason != "" {
			return omit(reason)
		}
		payload = decoded
		body.OriginalEncoding = encoding
	}

	descriptor := method.Output()
	if in.Request {
		descriptor = method.Input()
	}
	message := dynamicpb.NewMessage(descriptor)
	if err := protoset.Unmarshal(payload, message); err != nil {
		return omit(ReasonProtoMalformed)
	}
	var walk protoWalk
	e.sanitizeMessage(location, message, hits, &walk)
	result.Message = message
	switch {
	case walk.unknown:
		return omit(ReasonProtoUnknownFields)
	case walk.anyUnresolved:
		return omit(ReasonProtoAnyUnresolved)
	}

	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return omit(ReasonProtoMalformed)
	}
	if len(data) == 0 {
		body.State = traffic.BodyEmpty
	} else {
		body.State = traffic.BodyPresent
		body.Data = data
	}
	result.BodyResult = BodyResult{Body: body}
	return result
}

// sanitizeMessage applies the field rules wherever a covered message type appears, at
// any depth, including inside lists, map values and a google.protobuf.Any whose type the
// set describes. Rules match by full field name, so they follow the type, not a path.
func (e *Engine) sanitizeMessage(location Location, message protoreflect.Message, hits *Hits, walk *protoWalk) {
	if len(message.GetUnknown()) > 0 {
		walk.unknown = true
	}
	if message.Descriptor().FullName() == "google.protobuf.Any" {
		e.sanitizeAny(location, message, hits, walk)
		return
	}

	// Collected first: a message mustn't be changed while it is being ranged over.
	var covered, nested []protoreflect.FieldDescriptor
	message.Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		switch {
		case e.protoRules[field.FullName()] != "":
			covered = append(covered, field)
		case field.IsMap() && field.MapValue().Message() != nil, !field.IsMap() && field.Message() != nil:
			nested = append(nested, field)
		}
		return true
	})
	for _, field := range covered {
		hits.add(location, e.protoRules[field.FullName()], redactProtoField(message, field))
	}
	for _, field := range nested {
		switch {
		case field.IsMap():
			values := message.Mutable(field).Map()
			var keys []protoreflect.MapKey
			values.Range(func(key protoreflect.MapKey, _ protoreflect.Value) bool {
				keys = append(keys, key)
				return true
			})
			for _, key := range keys {
				e.sanitizeMessage(location, values.Mutable(key).Message(), hits, walk)
			}
		case field.IsList():
			list := message.Mutable(field).List()
			for i := range list.Len() {
				e.sanitizeMessage(location, list.Get(i).Message(), hits, walk)
			}
		default:
			e.sanitizeMessage(location, message.Mutable(field).Message(), hits, walk)
		}
	}
}

// redactProtoField replaces a covered field and returns how many values it replaced.
// Text and bytes keep their place with a placeholder. Anything else is cleared, because
// there is no value of those types that can't be mistaken for real data.
func redactProtoField(message protoreflect.Message, field protoreflect.FieldDescriptor) int {
	switch {
	case field.IsList():
		n := message.Get(field).List().Len()
		message.Clear(field)
		return n
	case field.IsMap():
		n := message.Get(field).Map().Len()
		message.Clear(field)
		return n
	case field.Kind() == protoreflect.StringKind:
		message.Set(field, protoreflect.ValueOfString(Placeholder))
	case field.Kind() == protoreflect.BytesKind:
		message.Set(field, protoreflect.ValueOfBytes([]byte(Placeholder)))
	default:
		message.Clear(field)
	}
	return 1
}

// sanitizeAny unpacks an Any whose type the set describes, sanitizes it, and packs it
// again. An Any of any other type is opaque bytes that no rule can see into.
func (e *Engine) sanitizeAny(location Location, message protoreflect.Message, hits *Hits, walk *protoWalk) {
	fields := message.Descriptor().Fields()
	typeField, valueField := fields.ByName("type_url"), fields.ByName("value")
	typeURL := message.Get(typeField).String()
	value := message.Get(valueField).Bytes()
	if typeURL == "" && len(value) == 0 {
		return
	}
	descriptor, err := e.descriptors.MessageByURL(typeURL)
	if err != nil {
		walk.anyUnresolved = true
		return
	}
	inner := dynamicpb.NewMessage(descriptor)
	if err := protoset.Unmarshal(value, inner); err != nil {
		walk.anyUnresolved = true
		return
	}
	e.sanitizeMessage(location, inner, hits, walk)
	packed, err := proto.MarshalOptions{Deterministic: true}.Marshal(inner)
	if err != nil {
		walk.anyUnresolved = true
		return
	}
	message.Set(valueField, protoreflect.ValueOfBytes(packed))
}
