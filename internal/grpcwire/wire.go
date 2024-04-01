// Package grpcwire reads and writes the parts of the gRPC protocol over HTTP/2 that
// capture and replay need: message framing, status, and timeouts. It holds no opinion
// about message contents.
//
// See https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md.
package grpcwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HeaderSize is the size of the prefix on each message: a one-byte compressed flag
// followed by a four-byte big-endian length.
const HeaderSize = 5

// ErrMalformedFrame means data isn't a sequence of length-prefixed messages. Errors
// never hold the content, since it hasn't been sanitized.
var ErrMalformedFrame = errors.New("malformed gRPC frame")

// Kind classifies a Content-Type.
type Kind int

const (
	// KindNone isn't gRPC. That includes gRPC-Web, which has its own framing rules.
	KindNone Kind = iota
	// KindProto is gRPC with Protocol Buffers messages.
	KindProto
	// KindOtherCodec is gRPC with messages in another format, which can't be interpreted.
	KindOtherCodec
)

// ContentKind classifies a Content-Type.
func ContentKind(contentType string) Kind {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return KindNone
	}
	switch {
	case mediaType == "application/grpc", mediaType == "application/grpc+proto":
		return KindProto
	case strings.HasPrefix(mediaType, "application/grpc+"):
		return KindOtherCodec
	default:
		return KindNone
	}
}

// Frame is one length-prefixed message. Payload aliases the parsed data.
type Frame struct {
	Compressed bool
	Payload    []byte
}

// ParseFrames splits data into messages. Every byte must belong to a complete frame.
// Lengths are checked against what's actually present, so nothing is allocated from a
// declared length.
func ParseFrames(data []byte) ([]Frame, error) {
	var frames []Frame
	for len(data) > 0 {
		if len(data) < HeaderSize {
			return nil, fmt.Errorf("%w: incomplete header", ErrMalformedFrame)
		}
		flag := data[0]
		if flag > 1 {
			return nil, fmt.Errorf("%w: undefined compressed flag", ErrMalformedFrame)
		}
		length := uint64(binary.BigEndian.Uint32(data[1:HeaderSize]))
		if length > uint64(len(data)-HeaderSize) {
			return nil, fmt.Errorf("%w: length exceeds the data", ErrMalformedFrame)
		}
		end := HeaderSize + int(length) //nolint:gosec // Bounded by len(data) above.
		frames = append(frames, Frame{Compressed: flag == 1, Payload: data[HeaderSize:end]})
		data = data[end:]
	}
	return frames, nil
}

// AppendFrame appends one length-prefixed message to dst. The payload must already be
// compressed if compressed is true.
func AppendFrame(dst, payload []byte, compressed bool) []byte {
	var flag byte
	if compressed {
		flag = 1
	}
	dst = append(dst, flag)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(payload))) //nolint:gosec // Message sizes are far below 4 GiB.
	return append(dst, payload...)
}

// Status returns a response's gRPC status. It normally arrives in the trailers, but a
// Trailers-Only response carries it in the single HEADERS block. A valid response always
// has one, so ok is false for a missing or invalid value.
func Status(header, trailer http.Header) (code int, ok bool) {
	value := trailer.Get("Grpc-Status")
	if value == "" {
		value = header.Get("Grpc-Status")
	}
	code, err := strconv.Atoi(value)
	if err != nil || code < 0 || code > 255 {
		return 0, false
	}
	return code, true
}

var statusNames = [...]string{
	"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND",
	"ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
	"ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS",
	"UNAUTHENTICATED",
}

// StatusName returns a status code's name.
func StatusName(code int) string {
	if code >= 0 && code < len(statusNames) {
		return statusNames[code]
	}
	return "CODE_" + strconv.Itoa(code)
}

// IsServerFault reports whether a status means the server failed, rather than giving an
// answer to the request. This is the gRPC counterpart of an HTTP 5xx. A code this build
// doesn't know counts as a fault, since nothing says it's an answer.
func IsServerFault(code int) bool {
	switch code {
	case 2, 4, 8, 12, 13, 14, 15:
		return true
	}
	return code >= len(statusNames)
}

// FormatTimeout renders a grpc-timeout value: at most eight digits and a unit, using the
// smallest unit that fits. It rounds up, so a deadline is never shorter than asked for,
// and returns "" for a duration with no meaningful timeout.
func FormatTimeout(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	const maxValue = 99_999_999
	for _, unit := range []struct {
		size   time.Duration
		symbol string
	}{
		{time.Nanosecond, "n"},
		{time.Microsecond, "u"},
		{time.Millisecond, "m"},
		{time.Second, "S"},
		{time.Minute, "M"},
	} {
		if value := ceilDiv(d, unit.size); value <= maxValue {
			return strconv.FormatInt(value, 10) + unit.symbol
		}
	}
	return strconv.FormatInt(ceilDiv(d, time.Hour), 10) + "H"
}

func ceilDiv(d, unit time.Duration) int64 {
	value := int64(d / unit)
	if d%unit != 0 {
		value++
	}
	return value
}
