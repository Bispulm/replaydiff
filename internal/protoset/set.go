// Package protoset loads compiled Protocol Buffers descriptors. A descriptor set is what
// lets gRPC messages be interpreted offline, without generated code, so that redaction
// and comparison are reproducible from a file you can review and version.
package protoset

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// ErrUnknownMethod means an RPC isn't described by the set.
var ErrUnknownMethod = errors.New("method isn't in the descriptor set")

// MaxAnyDepth is how many levels of google.protobuf.Any are unpacked inside one another.
// Each is decoded on its own, so protobuf's nesting limit doesn't cover them, and every
// level holds a copy of what it packs: unbounded, the cost grows with the square of the
// message size.
const MaxAnyDepth = 8

// ErrMalformed means bytes didn't decode as the message.
var ErrMalformed = errors.New("malformed protobuf message")

// Unmarshal decodes untrusted bytes into a message. protobuf-go can panic rather than
// fail on a malformed map entry in a dynamic message (as of v1.36.12, when the entry
// repeats its key with the wrong wire type), so a panic is reported as ErrMalformed. The
// message's contents are undefined after an error.
//
// Required fields aren't checked. A missing one is a difference to report, and redaction
// itself clears covered required fields.
func Unmarshal(data []byte, message proto.Message) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("%w: the decoder failed", ErrMalformed)
		}
	}()
	if err := (proto.UnmarshalOptions{AllowPartial: true}).Unmarshal(data, message); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return nil
}

// MethodDescriptor describes an RPC.
type MethodDescriptor = protoreflect.MethodDescriptor

// Set is a loaded descriptor set. It is safe for concurrent use.
type Set struct {
	files  *protoregistry.Files
	types  *dynamicpb.Types
	digest string
}

// Load reads a descriptor set from a file, as written by protoc --descriptor_set_out
// with --include_imports.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path) //nolint:gosec // The path is the operator's own flag.
	if err != nil {
		return nil, fmt.Errorf("read descriptor set: %w", err)
	}
	return Parse(data)
}

// Parse decodes a descriptor set.
func Parse(data []byte) (*Set, error) {
	var files descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(data, &files); err != nil {
		return nil, fmt.Errorf("parse descriptor set: %w", err)
	}
	if len(files.GetFile()) == 0 {
		return nil, errors.New("parse descriptor set: it holds no files")
	}
	resolved, err := protodesc.NewFiles(&files)
	if err != nil {
		return nil, fmt.Errorf("parse descriptor set: %w (was it built with --include_imports?)", err)
	}
	sum := sha256.Sum256(data)
	return &Set{files: resolved, types: dynamicpb.NewTypes(resolved), digest: hex.EncodeToString(sum[:16])}, nil
}

// Types resolves message types by name and URL, for encoders that need one.
func (s *Set) Types() *dynamicpb.Types { return s.types }

// Digest identifies the set's content. Records store it, so that a recording can be
// matched with the schema that sanitized it.
func (s *Set) Digest() string { return s.digest }

// Method finds an RPC by its path, such as /package.Service/Method.
func (s *Set) Method(rpc string) (MethodDescriptor, error) {
	service, method, ok := strings.Cut(strings.TrimPrefix(rpc, "/"), "/")
	if !strings.HasPrefix(rpc, "/") || !ok || service == "" || method == "" || strings.Contains(method, "/") {
		return nil, ErrUnknownMethod
	}
	descriptor, err := s.files.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return nil, ErrUnknownMethod //nolint:errorlint // The registry's error adds nothing.
	}
	serviceDescriptor, ok := descriptor.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, ErrUnknownMethod
	}
	found := serviceDescriptor.Methods().ByName(protoreflect.Name(method))
	if found == nil {
		return nil, ErrUnknownMethod
	}
	return found, nil
}

// IsStreaming reports whether an RPC streams in either direction.
func IsStreaming(method MethodDescriptor) bool {
	return method.IsStreamingClient() || method.IsStreamingServer()
}

// Field finds a field by its full name, such as package.Message.field.
func (s *Set) Field(fullName string) (protoreflect.FieldDescriptor, error) {
	descriptor, err := s.files.FindDescriptorByName(protoreflect.FullName(fullName))
	if err != nil {
		return nil, fmt.Errorf("field %q isn't in the descriptor set", fullName)
	}
	field, ok := descriptor.(protoreflect.FieldDescriptor)
	if !ok {
		return nil, fmt.Errorf("%q isn't a field", fullName)
	}
	return field, nil
}

// MessageByURL finds the message type a google.protobuf.Any names.
func (s *Set) MessageByURL(typeURL string) (protoreflect.MessageDescriptor, error) {
	_, name, ok := strings.Cut(typeURL, "/")
	if !ok || name == "" {
		return nil, errors.New("not a type URL")
	}
	descriptor, err := s.files.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, errors.New("type isn't in the descriptor set")
	}
	message, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, errors.New("not a message type")
	}
	return message, nil
}
