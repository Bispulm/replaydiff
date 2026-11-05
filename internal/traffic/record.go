// Package traffic defines the on-disk recording format: a versioned record
// schema stored in independently readable, checksummed segment files. See
// docs/traffic-format.md for the byte layout.
//
// Recorded data is treated as untrusted when read. Files can be damaged or
// handcrafted, so nothing read from them is believed until validated.
package traffic

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is the record schema this build reads and writes. Any change
// in meaning requires a new version, and readers reject versions they don't
// know rather than guessing.
const SchemaVersion = 1

// Limits enforced on every record read from disk.
const (
	MaxIDBytes         = 64
	MaxSessionKeyBytes = 128
	MaxMethodBytes     = 32
	MaxPathBytes       = 64 << 10
	MaxQueryBytes      = 64 << 10
	MaxHeaders         = 512
	MaxHeaderNameBytes = 256
)

// Protocol identifies the protocol observed at capture.
type Protocol string

// Supported protocols.
const (
	ProtocolHTTP10 Protocol = "http/1.0"
	ProtocolHTTP11 Protocol = "http/1.1"
	ProtocolHTTP2  Protocol = "h2"
	ProtocolGRPC   Protocol = "grpc"
)

// BodyState says what is known about a body. The states are deliberately
// distinct: an empty body is evidence, an omitted one is the absence of it.
type BodyState string

// Body states.
const (
	// BodyPresent means Data holds the sanitized body.
	BodyPresent BodyState = "present"
	// BodyEmpty means the body was observed and had no bytes.
	BodyEmpty BodyState = "empty"
	// BodyOmitted means the body was observed but deliberately not stored.
	BodyOmitted BodyState = "omitted"
	// BodyTruncated means the body ended early on the wire.
	BodyTruncated BodyState = "truncated"
	// BodyUnavailable means the body was never observed.
	BodyUnavailable BodyState = "unavailable"
)

// TransportOutcome describes how the live exchange ended.
type TransportOutcome string

// Transport outcomes.
const (
	TransportOK             TransportOutcome = "ok"
	TransportUpstreamError  TransportOutcome = "upstream_error"
	TransportUpstreamAbort  TransportOutcome = "upstream_aborted"
	TransportClientCanceled TransportOutcome = "client_canceled"
)

// Body is a sanitized message body. Data is stored decompressed, so
// OriginalEncoding records what was on the wire.
type Body struct {
	State            BodyState `json:"state"`
	Reason           string    `json:"reason,omitempty"`
	ContentType      string    `json:"content_type,omitempty"`
	OriginalEncoding string    `json:"original_encoding,omitempty"`
	ObservedBytes    int64     `json:"observed_bytes,omitempty"`
	Data             []byte    `json:"data,omitempty"`
}

// Request is sanitized request metadata and body. The destination is not part
// of it: replay takes its target only from validated configuration.
type Request struct {
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	RawQuery string              `json:"raw_query,omitempty"`
	Headers  map[string][]string `json:"headers,omitempty"`
	Trailers map[string][]string `json:"trailers,omitempty"`
	Body     Body                `json:"body"`
}

// Response is sanitized response metadata and body. HTTP and gRPC status are
// separate because a gRPC failure normally arrives with HTTP status 200.
type Response struct {
	StatusCode  int                 `json:"status_code"`
	GRPCStatus  *int                `json:"grpc_status,omitempty"`
	GRPCMessage string              `json:"grpc_message,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	Trailers    map[string][]string `json:"trailers,omitempty"`
	Body        Body                `json:"body"`
}

// Timing holds durations measured at the proxy.
type Timing struct {
	HeadersMicros int64 `json:"headers_us,omitempty"`
	TotalMicros   int64 `json:"total_us"`
}

// Outcome records how the live exchange ended.
type Outcome struct {
	Transport TransportOutcome `json:"transport"`
}

// RedactionHit counts how many values a rule replaced at a location. Rule is
// the configured rule text, never text taken from the traffic.
type RedactionHit struct {
	Location string `json:"location"`
	Rule     string `json:"rule"`
	Count    int    `json:"count"`
}

// Redaction describes what the policy did to a record. Complete is false when
// any part of the record was withheld because it couldn't be sanitized.
type Redaction struct {
	PolicyDigest string         `json:"policy_digest,omitempty"`
	Complete     bool           `json:"complete"`
	Hits         []RedactionHit `json:"hits,omitempty"`
}

// ReplayInfo records whether capture believes the request can be reproduced.
// It says nothing about whether replaying it is safe; that is decided by the
// replay policy.
type ReplayInfo struct {
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason,omitempty"`
}

// DescriptorRef identifies the protobuf descriptor set needed to interpret a
// record's bodies.
type DescriptorRef struct {
	SetDigest string `json:"set_digest"`
}

// Record is one captured exchange.
type Record struct {
	SchemaVersion int `json:"schema_version"`
	// ID is a stable identifier for this record.
	ID string `json:"id"`
	// Seq is assigned when the request arrives, per capture run. Files are
	// written in completion order, so Seq is what restores arrival order.
	Seq        uint64    `json:"seq"`
	CapturedAt time.Time `json:"captured_at"`
	// SessionKey is a keyed digest, never the session identifier itself.
	SessionKey string         `json:"session_key,omitempty"`
	Protocol   Protocol       `json:"protocol"`
	RPC        string         `json:"rpc,omitempty"`
	Descriptor *DescriptorRef `json:"descriptor,omitempty"`
	Request    Request        `json:"request"`
	// Response is nil when no response was observed.
	Response  *Response  `json:"response,omitempty"`
	Timing    Timing     `json:"timing"`
	Outcome   Outcome    `json:"outcome"`
	Redaction Redaction  `json:"redaction"`
	Replay    ReplayInfo `json:"replay"`
}

const idAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns a 26 character identifier that sorts by time: 48 bits of
// milliseconds followed by 80 random bits, in Crockford base32.
func NewID(t time.Time) string {
	var raw [16]byte
	ms := uint64(t.UnixMilli()) //nolint:gosec // Times before 1970 aren't produced.
	for i := range 6 {
		raw[i] = byte(ms >> (40 - 8*i))
	}
	_, _ = rand.Read(raw[6:]) // crypto/rand.Read never returns an error.

	// Encodes 130 bits: two zero bits, then the 128 bits of raw.
	var out [26]byte
	var acc uint32
	bits := 2
	pos := 0
	for _, b := range raw {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out[pos] = idAlphabet[(acc>>bits)&31]
			pos++
		}
	}
	return string(out[:])
}

// ErrInvalidRecord wraps every validation failure.
var ErrInvalidRecord = errors.New("invalid record")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRecord, fmt.Sprintf(format, args...))
}

// Validate checks structure and bounds. Its errors name the field but never
// quote its content, since content can hold values that must not reach logs.
func (r *Record) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return invalid("schema version")
	}
	if !isIdentifier(r.ID, MaxIDBytes) {
		return invalid("id")
	}
	if r.Seq == 0 {
		return invalid("seq")
	}
	if r.CapturedAt.IsZero() {
		return invalid("captured_at")
	}
	if len(r.SessionKey) > MaxSessionKeyBytes || !isHex(r.SessionKey) {
		return invalid("session_key")
	}
	switch r.Protocol {
	case ProtocolHTTP10, ProtocolHTTP11, ProtocolHTTP2, ProtocolGRPC:
	default:
		return invalid("protocol")
	}
	// An RPC is a method path, and replay sends it as the request path.
	if r.RPC != "" && (len(r.RPC) > MaxPathBytes || !strings.HasPrefix(r.RPC, "/") || hasControl(r.RPC) || strings.ContainsRune(r.RPC, ' ')) {
		return invalid("rpc")
	}
	if r.Descriptor != nil && (len(r.Descriptor.SetDigest) > MaxSessionKeyBytes || !isHex(r.Descriptor.SetDigest)) {
		return invalid("descriptor")
	}
	if r.Timing.HeadersMicros < 0 || r.Timing.TotalMicros < 0 {
		return invalid("timing")
	}
	switch r.Outcome.Transport {
	case TransportOK, TransportUpstreamError, TransportUpstreamAbort, TransportClientCanceled:
	default:
		return invalid("outcome")
	}
	for _, hit := range r.Redaction.Hits {
		if hit.Count < 0 {
			return invalid("redaction count")
		}
	}
	if err := r.Request.validate(); err != nil {
		return err
	}
	if r.Response != nil {
		return r.Response.validate()
	}
	return nil
}

func (q *Request) validate() error {
	if len(q.Method) > MaxMethodBytes || !isToken(q.Method) {
		return invalid("request method")
	}
	if len(q.Path) > MaxPathBytes || !validPath(q.Path) {
		return invalid("request path")
	}
	if len(q.RawQuery) > MaxQueryBytes || hasControl(q.RawQuery) {
		return invalid("request query")
	}
	if err := validateHeaders("request headers", q.Headers); err != nil {
		return err
	}
	if err := validateHeaders("request trailers", q.Trailers); err != nil {
		return err
	}
	return q.Body.validate("request body")
}

func (p *Response) validate() error {
	if p.StatusCode < 100 || p.StatusCode > 999 {
		return invalid("response status")
	}
	if p.GRPCStatus != nil && (*p.GRPCStatus < 0 || *p.GRPCStatus > 255) {
		return invalid("response grpc status")
	}
	if err := validateHeaders("response headers", p.Headers); err != nil {
		return err
	}
	if err := validateHeaders("response trailers", p.Trailers); err != nil {
		return err
	}
	return p.Body.validate("response body")
}

func (b *Body) validate(field string) error {
	switch b.State {
	case BodyPresent:
		if len(b.Data) == 0 {
			return invalid("%s has no data", field)
		}
	case BodyEmpty, BodyOmitted, BodyTruncated, BodyUnavailable:
		if len(b.Data) != 0 {
			return invalid("%s holds data in state %s", field, b.State)
		}
	default:
		return invalid("%s state", field)
	}
	if b.ObservedBytes < 0 {
		return invalid("%s observed bytes", field)
	}
	return nil
}

func validateHeaders(field string, headers map[string][]string) error {
	if len(headers) > MaxHeaders {
		return invalid("%s count", field)
	}
	for name, values := range headers {
		if len(name) > MaxHeaderNameBytes || !isToken(name) {
			return invalid("%s name", field)
		}
		for _, value := range values {
			if hasControlExceptTab(value) {
				return invalid("%s value", field)
			}
		}
	}
	return nil
}

// validPath accepts origin-form paths and the OPTIONS asterisk form. Absolute
// URLs are rejected, so a record can never name a destination.
func validPath(path string) bool {
	if path == "*" {
		return true
	}
	return strings.HasPrefix(path, "/") && !hasControl(path) && !strings.ContainsRune(path, ' ')
}

func isIdentifier(s string, maxBytes int) bool {
	if s == "" || len(s) > maxBytes {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isToken reports whether s is an RFC 9110 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	for i := range len(s) {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func hasControlExceptTab(s string) bool {
	for i := range len(s) {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return true
		}
	}
	return false
}
