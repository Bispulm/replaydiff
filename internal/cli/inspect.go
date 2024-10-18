package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/Bispulm/replaydiff/internal/protoset"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

const inspectUsage = `Usage: replaydiff inspect --traffic DIR [flags]

Print stored records as JSON lines, one record per line, with text bodies
decoded so they can be read and reviewed. Use this to check what redaction left
in a recording before sharing it. With --descriptor-set, gRPC messages recorded
with that set are shown as JSON.

Exits 2 if the dataset is damaged or incomplete, after printing what is readable.

`

// inspectedBody is a stored body with its data shown as text where possible.
type inspectedBody struct {
	traffic.Body
	Data       []byte          `json:"data,omitempty"`
	DataText   string          `json:"data_text,omitempty"`
	DataBase64 []byte          `json:"data_base64,omitempty"`
	DataProto  json.RawMessage `json:"data_proto,omitempty"`
}

func inspectBody(body traffic.Body, message json.RawMessage) inspectedBody {
	out := inspectedBody{Body: body}
	if message != nil {
		out.DataProto = message
		return out
	}
	if utf8.Valid(body.Data) {
		out.DataText = string(body.Data)
	} else {
		out.DataBase64 = body.Data
	}
	return out
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dir := fs.String("traffic", "", "directory of traffic segments (required)")
	limit := fs.Int("limit", 0, "print at most this many records; 0 prints all")
	descriptorPath := fs.String("descriptor-set", "", descriptorSetUsage)
	fs.Usage = func() {
		fmt.Fprint(stderr, inspectUsage)
		fs.PrintDefaults()
	}
	help, err := parseFlags(fs, args, stderr)
	if help {
		return ExitOK
	}
	if err != nil {
		return fail(stderr, "inspect", err)
	}
	if *dir == "" {
		return fail(stderr, "inspect", errors.New("--traffic is required"))
	}
	descriptors, err := loadDescriptors(*descriptorPath)
	if err != nil {
		return fail(stderr, "inspect", err)
	}
	messages := messageReader{set: descriptors}
	dataset, err := traffic.Scan(*dir, traffic.ScanOptions{})
	if err != nil {
		return fail(stderr, "inspect", err)
	}
	defer func() { _ = dataset.Close() }()

	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	for i, entry := range dataset.Entries {
		if *limit > 0 && i >= *limit {
			break
		}
		rec, err := dataset.Load(entry)
		if err != nil {
			return fail(stderr, "inspect", err)
		}
		if err := enc.Encode(inspectable(rec, &messages)); err != nil {
			return fail(stderr, "inspect", err)
		}
	}

	fmt.Fprintf(stderr, "%d record(s) in %d segment(s)\n", dataset.Integrity.Records, dataset.Integrity.Segments)
	if messages.mismatched > 0 {
		fmt.Fprintf(stderr, "%d gRPC record(s) were made with another descriptor set, so their messages aren't decoded\n", messages.mismatched)
	}
	for _, reason := range sortedKeys(dataset.CaptureDrops) {
		fmt.Fprintf(stderr, "capture dropped %d exchange(s): %s\n", dataset.CaptureDrops[reason], reason)
	}
	if problems := dataset.Integrity.Problems(); len(problems) > 0 {
		for _, problem := range problems {
			fmt.Fprintf(stderr, "incomplete: %s\n", problem)
		}
		return ExitFailure
	}
	return ExitOK
}

// messageReader shows stored gRPC messages as JSON. It decodes only records made with the
// same descriptor set, since another schema could give the bytes other meanings.
type messageReader struct {
	set        *protoset.Set
	mismatched int
}

// method returns the RPC of a gRPC record made with the same descriptor set, or nil. It
// counts records made with another set.
func (m *messageReader) method(rec *traffic.Record) protoset.MethodDescriptor {
	if m.set == nil || rec.Protocol != traffic.ProtocolGRPC {
		return nil
	}
	if rec.Descriptor == nil || rec.Descriptor.SetDigest != m.set.Digest() {
		m.mismatched++
		return nil
	}
	method, err := m.set.Method(rec.RPC)
	if err != nil {
		return nil
	}
	return method
}

// read returns a stored message as JSON, or nil. Stored messages were redacted when they
// were recorded.
func (m *messageReader) read(descriptor protoreflect.MessageDescriptor, body traffic.Body) json.RawMessage {
	if descriptor == nil || body.State != traffic.BodyPresent {
		return nil
	}
	message := dynamicpb.NewMessage(descriptor)
	if protoset.Unmarshal(body.Data, message) != nil {
		return nil
	}
	data, err := protojson.MarshalOptions{Resolver: m.set.Types()}.Marshal(message)
	if err != nil {
		return nil
	}
	return data
}

// inspectable mirrors traffic.Record, replacing its bodies with readable forms.
func inspectable(rec *traffic.Record, messages *messageReader) any {
	type request struct {
		traffic.Request
		Body inspectedBody `json:"body"`
	}
	type response struct {
		traffic.Response
		Body inspectedBody `json:"body"`
	}
	type record struct {
		*traffic.Record
		Request  request   `json:"request"`
		Response *response `json:"response,omitempty"`
	}
	var input, output protoreflect.MessageDescriptor
	if method := messages.method(rec); method != nil {
		input, output = method.Input(), method.Output()
	}
	out := record{Record: rec, Request: request{Request: rec.Request, Body: inspectBody(rec.Request.Body, messages.read(input, rec.Request.Body))}}
	if rec.Response != nil {
		out.Response = &response{Response: *rec.Response, Body: inspectBody(rec.Response.Body, messages.read(output, rec.Response.Body))}
	}
	return out
}
