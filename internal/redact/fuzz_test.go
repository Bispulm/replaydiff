package redact

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bispulm/replaydiff/internal/traffic"
)

const fuzzPolicy = `
query_params: [token]
json_paths: ["$.secret", "$..password", "$.items[*].card"]
`

// FuzzBody checks the fail-closed contract on arbitrary input: a body is either
// stored as valid sanitized content, or nothing is stored at all.
func FuzzBody(f *testing.F) {
	f.Add([]byte(`{"secret":"x","items":[{"card":"y"}]}`), "application/json", "")
	f.Add([]byte(`{"secret":`), "application/json", "")
	f.Add([]byte(`token=a&b=c`), "application/x-www-form-urlencoded", "")
	f.Add([]byte{0x1f, 0x8b, 0x08}, "application/json", "gzip")
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd}, "application/json", "zstd")
	f.Add([]byte("x"), "text/plain", "br")

	policy, err := ParsePolicy([]byte(fuzzPolicy))
	if err != nil {
		f.Fatal(err)
	}
	engine, err := NewEngine(policy, Options{MaxDecompressedBytes: 1 << 20})
	if err != nil {
		f.Fatal(err)
	}
	defer engine.Close()

	f.Fuzz(func(t *testing.T, data []byte, contentType, encoding string) {
		res := engine.Body(ResponseBody, BodyInput{ContentType: contentType, ContentEncoding: encoding, Data: data}, &Hits{})
		switch res.Body.State {
		case traffic.BodyPresent:
			if res.Failed {
				t.Fatal("failed result holds data")
			}
			if isJSONType(res.Body.ContentType) && !json.Valid(res.Body.Data) {
				t.Fatalf("stored invalid JSON: %q", res.Body.Data)
			}
		case traffic.BodyEmpty, traffic.BodyOmitted:
			if len(res.Body.Data) != 0 {
				t.Fatalf("state %s holds data", res.Body.State)
			}
		case traffic.BodyTruncated, traffic.BodyUnavailable:
			t.Fatalf("unexpected state %s", res.Body.State)
		}
	})
}

// FuzzQuery checks that a value following a listed parameter name never
// survives, whatever surrounds it.
func FuzzQuery(f *testing.F) {
	f.Add("a=1&b=2", "plantedvalue")
	f.Add("%zz=1;a", "plantedvalue")
	f.Add("=&=&", "plantedvalue")

	policy, err := ParsePolicy([]byte(fuzzPolicy))
	if err != nil {
		f.Fatal(err)
	}
	engine, err := NewEngine(policy, Options{})
	if err != nil {
		f.Fatal(err)
	}
	defer engine.Close()

	const replacement = queryPlaceholder + "token"
	f.Fuzz(func(t *testing.T, prefix, value string) {
		if strings.ContainsAny(value, "&;") || len(value) < 8 || strings.Contains(prefix, value) || strings.Contains(replacement, value) {
			t.Skip()
		}
		got := engine.Query(prefix+"&token="+value, &Hits{})
		if strings.Contains(got, value) {
			t.Fatalf("value survived: %q", got)
		}
	})
}

// FuzzHeaders checks URL handling on arbitrary header values doesn't panic and
// never returns a value containing a planted query parameter.
func FuzzHeaders(f *testing.F) {
	f.Add("https://a.example.test/?x=1")
	f.Add("http://[bad")
	f.Add("%zz")

	policy, err := ParsePolicy([]byte(fuzzPolicy))
	if err != nil {
		f.Fatal(err)
	}
	engine, err := NewEngine(policy, Options{})
	if err != nil {
		f.Fatal(err)
	}
	defer engine.Close()

	const planted = "plantedheadervalue"
	f.Fuzz(func(t *testing.T, value string) {
		if strings.Contains(value, planted) {
			t.Skip()
		}
		got := engine.Headers(ResponseHeader, http.Header{"Location": {value + "?token=" + planted}}, &Hits{})
		for _, v := range got["Location"] {
			if strings.Contains(v, planted) {
				t.Fatalf("value survived: %q", v)
			}
		}
	})
}
