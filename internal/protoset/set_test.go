package protoset

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const fixtureSet = "../fixture/proto/orders.binpb"

func loadFixture(t *testing.T) *Set {
	t.Helper()
	set, err := Load(fixtureSet)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestMethodLookup(t *testing.T) {
	set := loadFixture(t)
	method, err := set.Method("/fixture.orders.v1.OrderService/GetOrder")
	if err != nil {
		t.Fatal(err)
	}
	if string(method.Input().FullName()) != "fixture.orders.v1.GetOrderRequest" || string(method.Output().FullName()) != "fixture.orders.v1.Order" {
		t.Fatalf("method = %v", method)
	}
	for _, rpc := range []string{
		"/fixture.orders.v1.OrderService/Nope",
		"/fixture.orders.v1.Nope/GetOrder",
		"/fixture.orders.v1.Order/GetOrder",
		"/nothing.here/GetOrder",
		"fixture.orders.v1.OrderService/GetOrder",
		"/fixture.orders.v1.OrderService",
		"/fixture.orders.v1.OrderService/GetOrder/extra",
		"",
		"/",
	} {
		if _, err := set.Method(rpc); !errors.Is(err, ErrUnknownMethod) {
			t.Errorf("Method(%q) err = %v, want ErrUnknownMethod", rpc, err)
		}
	}
}

func TestStreamingMethodsAreRecognized(t *testing.T) {
	set := loadFixture(t)
	if !IsStreaming(mustMethod(t, set, "/fixture.orders.v1.OrderService/WatchOrders")) {
		t.Fatal("WatchOrders streams")
	}
	if IsStreaming(mustMethod(t, set, "/fixture.orders.v1.OrderService/GetOrder")) {
		t.Fatal("GetOrder is unary")
	}
}

func mustMethod(t *testing.T, set *Set, rpc string) MethodDescriptor {
	t.Helper()
	method, err := set.Method(rpc)
	if err != nil {
		t.Fatal(err)
	}
	return method
}

func TestFieldLookup(t *testing.T) {
	set := loadFixture(t)
	field, err := set.Field("fixture.orders.v1.Customer.email")
	if err != nil {
		t.Fatal(err)
	}
	if string(field.Name()) != "email" {
		t.Fatalf("field = %v", field)
	}
	for _, name := range []string{"fixture.orders.v1.Customer.nope", "fixture.orders.v1.Nope.email", "email", "", "fixture.orders.v1.Customer"} {
		if _, err := set.Field(name); err == nil {
			t.Errorf("Field(%q): want error", name)
		}
	}
}

func TestDigestIdentifiesTheContent(t *testing.T) {
	first := loadFixture(t)
	if len(first.Digest()) != 32 || strings.Trim(first.Digest(), "0123456789abcdef") != "" {
		t.Fatalf("digest = %q", first.Digest())
	}
	if second := loadFixture(t); second.Digest() != first.Digest() {
		t.Fatal("the same file must have the same digest")
	}
	data, err := os.ReadFile(fixtureSet)
	if err != nil {
		t.Fatal(err)
	}
	var files descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(data, &files); err != nil {
		t.Fatal(err)
	}
	files.File = files.File[:len(files.File):len(files.File)]
	extra := &descriptorpb.FileDescriptorProto{Name: proto.String("extra.proto"), Package: proto.String("extra")}
	files.File = append(files.File, extra)
	changed, err := proto.Marshal(&files)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Parse(changed)
	if err != nil {
		t.Fatal(err)
	}
	if other.Digest() == first.Digest() {
		t.Fatal("different content must have a different digest")
	}
}

func TestLoadRejectsUnusableFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	noImports, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:       proto.String("a.proto"),
		Package:    proto.String("a"),
		Dependency: []string{"missing.proto"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := proto.Marshal(&descriptorpb.FileDescriptorSet{})
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing file":     filepath.Join(dir, "absent.binpb"),
		"not a descriptor": write("junk.binpb", []byte("this is not a descriptor set")),
		"missing imports":  write("imports.binpb", noImports),
		"no files":         write("empty.binpb", empty),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(path); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestAnyResolvesOnlyTypesInTheSet(t *testing.T) {
	set := loadFixture(t)
	if _, err := set.MessageByURL("type.googleapis.com/fixture.orders.v1.Customer"); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"type.googleapis.com/nothing.Here", "no-slash", ""} {
		if _, err := set.MessageByURL(url); err == nil {
			t.Errorf("MessageByURL(%q): want error", url)
		}
	}
}

// protobuf-go v1.36.12 panics decoding a map entry, in a dynamic message, that repeats its
// key with the wrong wire type. Untrusted bytes must fail to decode instead.
func TestUnmarshalReportsADecoderPanicAsAnError(t *testing.T) {
	set, err := Load(fixtureSet)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := set.MessageByURL("type.googleapis.com/fixture.orders.v1.Order")
	if err != nil {
		t.Fatal(err)
	}
	entry := protowire.AppendTag(nil, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, "k")
	entry = protowire.AppendTag(entry, 1, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 0)
	data := protowire.AppendBytes(protowire.AppendTag(nil, 7, protowire.BytesType), entry)

	if err := Unmarshal(data, dynamicpb.NewMessage(descriptor)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if err := Unmarshal([]byte{0xff}, dynamicpb.NewMessage(descriptor)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed for ordinary bad input", err)
	}
	if err := Unmarshal(nil, dynamicpb.NewMessage(descriptor)); err != nil {
		t.Fatalf("err = %v for an empty message", err)
	}
}
