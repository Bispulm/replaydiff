package grpcwire

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestContentTypeRecognition(t *testing.T) {
	for contentType, want := range map[string]Kind{
		"application/grpc":                KindProto,
		"application/grpc+proto":          KindProto,
		"APPLICATION/GRPC":                KindProto,
		"application/grpc; charset=utf-8": KindProto,
		"application/grpc+json":           KindOtherCodec,
		"application/grpc+thrift":         KindOtherCodec,
		"application/grpc-web":            KindNone,
		"application/grpc-web+proto":      KindNone,
		"application/json":                KindNone,
		"":                                KindNone,
		"not a type;;":                    KindNone,
	} {
		if got := ContentKind(contentType); got != want {
			t.Errorf("ContentKind(%q) = %v, want %v", contentType, got, want)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	data := AppendFrame(nil, []byte("hello"), false)
	data = AppendFrame(data, []byte{}, true)
	if !bytes.Equal(data[:5], []byte{0, 0, 0, 0, 5}) {
		t.Fatalf("header = %v", data[:5])
	}
	frames, err := ParseFrames(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || string(frames[0].Payload) != "hello" || frames[0].Compressed || len(frames[1].Payload) != 0 || !frames[1].Compressed {
		t.Fatalf("frames = %+v", frames)
	}
}

func TestParseNoFrames(t *testing.T) {
	frames, err := ParseFrames(nil)
	if err != nil || len(frames) != 0 {
		t.Fatalf("frames = %v, err = %v", frames, err)
	}
}

func TestParseRejectsMalformedFrames(t *testing.T) {
	for name, data := range map[string][]byte{
		"short header":            {0, 0, 0},
		"length past the end":     {0, 0, 0, 0, 9, 'a'},
		"huge length":             {0, 0xff, 0xff, 0xff, 0xff},
		"undefined flag":          {2, 0, 0, 0, 0},
		"flag above one":          {0x80, 0, 0, 0, 0},
		"trailing partial header": append(AppendFrame(nil, []byte("ok"), false), 0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFrames(data); !errors.Is(err, ErrMalformedFrame) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestParseFramesDoesNotCopyOrAllocateByTheDeclaredLength(t *testing.T) {
	data := []byte{0, 0x7f, 0xff, 0xff, 0xff}
	allocs := testing.AllocsPerRun(10, func() { _, _ = ParseFrames(data) })
	if allocs > 3 {
		t.Fatalf("allocs = %v", allocs)
	}
}

func TestStatusComesFromTrailersOrAHeadersOnlyResponse(t *testing.T) {
	code, ok := Status(http.Header{"Content-Type": {"application/grpc"}}, http.Header{"Grpc-Status": {"5"}})
	if !ok || code != 5 {
		t.Fatalf("trailers: %d, %t", code, ok)
	}
	// Trailers-Only: the status arrives in the only HEADERS block.
	code, ok = Status(http.Header{"Grpc-Status": {"7"}}, nil)
	if !ok || code != 7 {
		t.Fatalf("trailers-only: %d, %t", code, ok)
	}
	code, ok = Status(http.Header{"Grpc-Status": {"7"}}, http.Header{"Grpc-Status": {"0"}})
	if !ok || code != 0 {
		t.Fatalf("trailers must win: %d, %t", code, ok)
	}
	for name, header := range map[string]http.Header{
		"absent":       {},
		"not a number": {"Grpc-Status": {"nope"}},
		"negative":     {"Grpc-Status": {"-1"}},
		"too large":    {"Grpc-Status": {"256"}},
		"empty":        {"Grpc-Status": {""}},
	} {
		if _, ok := Status(header, nil); ok {
			t.Errorf("%s: want no status", name)
		}
	}
}

func TestStatusNames(t *testing.T) {
	for code, want := range map[int]string{0: "OK", 5: "NOT_FOUND", 13: "INTERNAL", 16: "UNAUTHENTICATED", 99: "CODE_99"} {
		if got := StatusName(code); got != want {
			t.Errorf("StatusName(%d) = %q, want %q", code, got, want)
		}
	}
}

// These are the codes that mean the server failed, as opposed to answering the request.
func TestServerFaultCodes(t *testing.T) {
	for code, want := range map[int]bool{
		0: false, 1: false, 2: true, 3: false, 4: true, 5: false, 6: false, 7: false, 8: true,
		9: false, 10: false, 11: false, 12: true, 13: true, 14: true, 15: true, 16: false, 99: true,
	} {
		if got := IsServerFault(code); got != want {
			t.Errorf("IsServerFault(%s) = %t, want %t", StatusName(code), got, want)
		}
	}
}

func TestTimeoutFormatFollowsTheSpec(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Nanosecond:         "1n",
		time.Microsecond:        "1000n",
		time.Millisecond:        "1000000n",
		1500 * time.Nanosecond:  "1500n",
		10 * time.Second:        "10000000u",
		100 * time.Second:       "100000m",
		99999999 * time.Second:  "99999999S",
		100000000 * time.Second: "1666667M",
		2000000 * time.Hour:     "2000000H",
		// Rounded up, so that a deadline is never shorter than the one asked for.
		100*time.Second + time.Nanosecond: "100001m",
	} {
		got := FormatTimeout(d)
		if got != want {
			t.Errorf("FormatTimeout(%v) = %q, want %q", d, got, want)
		}
		if digits := strings.TrimRight(got, "HMSmun"); len(digits) > 8 || len(digits) == 0 {
			t.Errorf("FormatTimeout(%v) = %q has %d digits; the spec allows at most 8", d, got, len(digits))
		}
	}
	if got := FormatTimeout(0); got != "" {
		t.Errorf("no timeout must mean no header, got %q", got)
	}
	if got := FormatTimeout(-time.Second); got != "" {
		t.Errorf("a negative timeout must mean no header, got %q", got)
	}
}

func FuzzParseFrames(f *testing.F) {
	f.Add(AppendFrame(nil, []byte("hello"), false))
	f.Add([]byte{1, 0, 0, 0, 1, 'x'})
	f.Add([]byte{0, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		frames, err := ParseFrames(data)
		if err != nil {
			return
		}
		var rebuilt []byte
		for _, frame := range frames {
			rebuilt = AppendFrame(rebuilt, frame.Payload, frame.Compressed)
		}
		if !bytes.Equal(rebuilt, data) {
			t.Fatalf("frames don't account for every byte: %v", data)
		}
	})
}
