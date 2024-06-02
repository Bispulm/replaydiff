package redact

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// requiredSet is a proto2 schema in which Secret.pin is required, and a response that
// carries a Secret in an Any.
func requiredSet(t *testing.T) *protoset.Set {
	t.Helper()
	s := proto.String
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	file := &descriptorpb.FileDescriptorProto{
		Name: s("legacy.proto"), Package: s("legacy"), Syntax: s("proto2"),
		Dependency: []string{"google/protobuf/any.proto"},
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: s("Secret"), Field: []*descriptorpb.FieldDescriptorProto{
				{Name: s("pin"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_REQUIRED.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum()},
			}},
			{Name: s("Reply"), Field: []*descriptorpb.FieldDescriptorProto{
				{Name: s("detail"), Number: proto.Int32(1), Label: optional, Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: s(".google.protobuf.Any")},
				{Name: s("secret"), Number: proto.Int32(2), Label: optional, Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: s(".legacy.Secret")},
			}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: s("Vault"), Method: []*descriptorpb.MethodDescriptorProto{
			{Name: s("Get"), InputType: s(".legacy.Reply"), OutputType: s(".legacy.Reply")},
		}}},
	}
	data, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		protodesc.ToFileDescriptorProto(anypb.File_google_protobuf_any_proto), file,
	}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := protoset.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

const vaultGet = "/legacy.Vault/Get"

func pinMessage(pin uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), pin)
}

func replyWithPinInAny(pin uint64) []byte {
	anyMessage := protowire.AppendTag(nil, 1, protowire.BytesType)
	anyMessage = protowire.AppendString(anyMessage, "type.googleapis.com/legacy.Secret")
	anyMessage = protowire.AppendTag(anyMessage, 2, protowire.BytesType)
	anyMessage = protowire.AppendBytes(anyMessage, pinMessage(pin))
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), anyMessage)
}

// Clearing a covered required field makes a strict encoder refuse the message. That once
// left the original bytes in the Any, where comparison decoded them.
func TestCoveredRequiredFieldsAreCleared(t *testing.T) {
	set := requiredSet(t)
	engine := protoEngine(t, "proto_fields: [legacy.Secret.pin]", set)
	const pin = 987654321
	for name, data := range map[string][]byte{
		"inside an Any": replyWithPinInAny(pin),
		"in a field":    protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), pinMessage(pin)),
	} {
		t.Run(name, func(t *testing.T) {
			res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: vaultGet, Data: framed(data)}, &Hits{})
			if res.Body.State != traffic.BodyPresent || res.Message == nil {
				t.Fatalf("result = %+v", res.BodyResult)
			}
			if bytes.Contains(res.Body.Data, pinMessage(pin)) {
				t.Fatalf("stored body still holds the covered value: %x", res.Body.Data)
			}
			kept, err := proto.MarshalOptions{AllowPartial: true}.Marshal(res.Message.Interface())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(kept, pinMessage(pin)) {
				t.Fatalf("the message kept for comparison still holds the covered value: %x", kept)
			}
		})
	}
}

// A required field the sender left out isn't a reason to discard the message. It's a
// difference comparison should report.
func TestMessagesMissingARequiredFieldAreKept(t *testing.T) {
	set := requiredSet(t)
	engine := protoEngine(t, "", set)
	emptySecret := protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), nil)
	res := engine.GRPCBody(ResponseBody, GRPCInput{RPC: vaultGet, Data: framed(emptySecret)}, &Hits{})
	if res.Body.State != traffic.BodyPresent || res.Failed {
		t.Fatalf("result = %+v", res.BodyResult)
	}
}
