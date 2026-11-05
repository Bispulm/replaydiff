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
)

// ErrUnknownMethod means an RPC isn't described by the set.
var ErrUnknownMethod = errors.New("method isn't in the descriptor set")

// MethodDescriptor describes an RPC.
type MethodDescriptor = protoreflect.MethodDescriptor

// Set is a loaded descriptor set. It is safe for concurrent use.
type Set struct {
	files  *protoregistry.Files
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
	return &Set{files: resolved, digest: hex.EncodeToString(sum[:16])}, nil
}

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
