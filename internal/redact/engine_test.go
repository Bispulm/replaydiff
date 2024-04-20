package redact

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/Bispulm/replaydiff/internal/traffic"
)

// sentinel returns a value unique to this call, so a match can only come from
// the input planted by this test.
func sentinel(t *testing.T) string {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "rdsentinel" + hex.EncodeToString(b[:])
}

// assertAbsent fails if the sentinel appears in v, in any encoding a stored
// form could use: plain, base64 at each alignment, or percent-encoded.
func assertAbsent(t *testing.T, secret string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if contains(data, secret) {
		t.Fatalf("sentinel leaked: %s", data)
	}
}

func contains(data []byte, secret string) bool {
	if bytes.Contains(data, []byte(secret)) || bytes.Contains(data, []byte(url.QueryEscape(secret))) {
		return true
	}
	for pad := range 3 {
		encoded := base64.StdEncoding.EncodeToString(append(make([]byte, pad), secret...))
		// Skip the characters affected by the leading padding and the end.
		core := encoded[(pad*8+5)/6 : len(encoded)-4]
		if bytes.Contains(data, []byte(core)) {
			return true
		}
	}
	return false
}

func TestAssertAbsentDetectsBase64Encoding(t *testing.T) {
	secret := sentinel(t)
	for pad := range 3 {
		body := traffic.Body{State: traffic.BodyPresent, Data: []byte(strings.Repeat("x", pad) + secret + "tail")}
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if !contains(data, secret) {
			t.Fatalf("scanner missed a base64 encoded sentinel at alignment %d: %s", pad, data)
		}
	}
}

func newEngine(t *testing.T, policyYAML string) *Engine {
	t.Helper()
	policy, err := ParsePolicy([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(policy, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return engine
}

func TestMandatoryHeadersAreRedactedWithAnEmptyPolicy(t *testing.T) {
	engine := newEngine(t, "")
	for _, name := range []string{
		"Authorization", "authorization", "AUTHORIZATION",
		"Cookie", "cookie",
		"Set-Cookie", "set-cookie", "SET-COOKIE",
		"X-Api-Key", "x-api-key", "X-API-KEY",
		"Proxy-Authorization",
	} {
		t.Run(name, func(t *testing.T) {
			secret := sentinel(t)
			var hits Hits
			got := engine.Headers(RequestHeader, http.Header{name: {secret, "second-" + secret}}, &hits)
			assertAbsent(t, secret, got)
			canonical := http.CanonicalHeaderKey(name)
			if !reflect.DeepEqual(got[canonical], []string{Placeholder}) {
				t.Fatalf("headers = %v", got)
			}
			if list := hits.List(); len(list) != 1 || list[0].Location != string(RequestHeader) {
				t.Fatalf("hits = %+v", list)
			}
		})
	}
}

func TestConfiguredHeadersAreRedactedCaseInsensitively(t *testing.T) {
	engine := newEngine(t, `headers: [X-Internal-Id]`)
	secret := sentinel(t)
	got := engine.Headers(ResponseHeader, http.Header{"x-internal-id": {secret}}, &Hits{})
	assertAbsent(t, secret, got)
}

func TestHeaderNamesThatLookSensitiveAreRedacted(t *testing.T) {
	engine := newEngine(t, "")
	for _, name := range []string{"X-Auth-Token", "X-Session-Id", "X-Client-Secret", "X-Db-Password", "X-Vault-Credential", "Api-Key"} {
		secret := sentinel(t)
		got := engine.Headers(RequestHeader, http.Header{name: {secret}}, &Hits{})
		assertAbsent(t, secret, got)
	}
}

func TestOrdinaryHeadersAreKept(t *testing.T) {
	engine := newEngine(t, "")
	in := http.Header{"Accept": {"application/json"}, "User-Agent": {"test"}, "X-Request-Seq": {"7"}}
	got := engine.Headers(RequestHeader, in, &Hits{})
	if !reflect.DeepEqual(got, map[string][]string(in)) {
		t.Fatalf("got %v", got)
	}
}

func TestHopByHopHeadersAreNotStored(t *testing.T) {
	engine := newEngine(t, "")
	got := engine.Headers(RequestHeader, http.Header{
		"Connection":        {"close, X-Conn-Scoped"},
		"X-Conn-Scoped":     {"value"},
		"Keep-Alive":        {"timeout=5"},
		"Proxy-Connection":  {"keep-alive"},
		"Te":                {"trailers"},
		"Trailer":           {"X-Checksum"},
		"Transfer-Encoding": {"chunked"},
		"Upgrade":           {"h2c"},
		"Accept":            {"*/*"},
	}, &Hits{})
	if !reflect.DeepEqual(got, map[string][]string{"Accept": {"*/*"}}) {
		t.Fatalf("got %v", got)
	}
}

// These describe the original bytes. A digest of an unredacted body would let
// a stored recording confirm guesses at a redacted value.
func TestHeadersDerivedFromTheBodyAreNotStored(t *testing.T) {
	engine := newEngine(t, "")
	got := engine.Headers(ResponseHeader, http.Header{
		"Content-Length":   {"10"},
		"Content-Encoding": {"gzip"},
		"Content-Md5":      {"x"},
		"Digest":           {"x"},
		"Content-Digest":   {"x"},
		"Repr-Digest":      {"x"},
		"Etag":             {`"x"`},
		"Content-Type":     {"application/json"},
	}, &Hits{})
	if !reflect.DeepEqual(got, map[string][]string{"Content-Type": {"application/json"}}) {
		t.Fatalf("got %v", got)
	}
}

func TestQueryRulesApplyToHeadersHoldingURLs(t *testing.T) {
	engine := newEngine(t, `query_params: [token]`)
	secret := sentinel(t)
	for _, name := range []string{"Referer", "Location", "Content-Location"} {
		got := engine.Headers(ResponseHeader, http.Header{name: {"https://svc.example.test/cb?token=" + secret + "&keep=1"}}, &Hits{})
		assertAbsent(t, secret, got)
		if !strings.Contains(got[name][0], "keep=1") {
			t.Errorf("%s lost an unrelated parameter: %v", name, got[name])
		}
	}
}

func TestQueryRulesApplyToURLFragments(t *testing.T) {
	engine := newEngine(t, `query_params: [access_token]`)
	secret := sentinel(t)
	got := engine.Headers(ResponseHeader, http.Header{"Location": {"https://svc.example.test/cb#access_token=" + secret + "&state=1"}}, &Hits{})
	assertAbsent(t, secret, got)
	if !strings.Contains(got["Location"][0], "state=1") {
		t.Fatalf("location = %v", got["Location"])
	}
}

// Hash-routed single-page apps put parameters after a path in the fragment.
func TestQueryRulesApplyToHashRoutedFragments(t *testing.T) {
	engine := newEngine(t, `query_params: [token]`)
	for _, prefix := range []string{"https://app.example.test/#?token=", "https://app.example.test/#/cb?token=", "0000#?token="} {
		secret := sentinel(t)
		got := engine.Headers(ResponseHeader, http.Header{"Location": {prefix + secret}}, &Hits{})
		assertAbsent(t, secret, got)
	}
}

func TestUnparsableURLHeaderIsRedactedWhole(t *testing.T) {
	engine := newEngine(t, `query_params: [token]`)
	secret := sentinel(t)
	got := engine.Headers(ResponseHeader, http.Header{"Location": {"http://[bad?token=" + secret}}, &Hits{})
	assertAbsent(t, secret, got)
}

func TestLinkHeaderWithAQueryIsRedactedWhole(t *testing.T) {
	engine := newEngine(t, `query_params: [token]`)
	secret := sentinel(t)
	got := engine.Headers(ResponseHeader, http.Header{"Link": {"<https://svc.example.test/?token=" + secret + `>; rel="next"`}}, &Hits{})
	assertAbsent(t, secret, got)
}

func TestQueryRedaction(t *testing.T) {
	engine := newEngine(t, `query_params: [token, api_key]`)
	tests := []struct {
		name string
		in   func(secret string) string
		want func(out string) bool
	}{
		{"named", func(s string) string { return "token=" + s }, func(o string) bool { return o == "token=REDACTED" }},
		{"case differs", func(s string) string { return "TOKEN=" + s }, func(o string) bool { return o == "TOKEN=REDACTED" }},
		{"percent encoded name", func(s string) string { return "%74oken=" + s }, func(o string) bool { return strings.HasSuffix(o, "=REDACTED") }},
		{"plus in name", func(s string) string { return "api_key=" + s + "+more" }, func(o string) bool { return o == "api_key=REDACTED" }},
		{"repeated", func(s string) string { return "token=" + s + "&token=" + s }, func(o string) bool { return o == "token=REDACTED&token=REDACTED" }},
		{"keeps order and others", func(s string) string { return "b=2&token=" + s + "&a=1" }, func(o string) bool { return o == "b=2&token=REDACTED&a=1" }},
		{"semicolon separator", func(s string) string { return "a=1;token=" + s }, func(o string) bool { return o == "a=1;token=REDACTED" }},
		{"malformed escape in name", func(s string) string { return "tok%zzen=" + s }, func(o string) bool { return strings.HasSuffix(o, "=REDACTED") }},
		{"malformed escape in value", func(s string) string { return "a=%zz" + s }, func(o string) bool { return o == "a=REDACTED" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := sentinel(t)
			var hits Hits
			got := engine.Query(tt.in(secret), &hits)
			assertAbsent(t, secret, got)
			if !tt.want(got) {
				t.Fatalf("query = %q", got)
			}
			if len(hits.List()) == 0 {
				t.Fatal("no hit recorded")
			}
		})
	}
}

// A listed parameter nested in another value is a covered value in a form a
// plain name match can't see, as in a redirect target or a malformed URL.
func TestListedParameterNestedInAValueIsRedacted(t *testing.T) {
	engine := newEngine(t, `query_params: [token]`)
	for _, in := range []func(string) string{
		func(s string) string { return "x=1?token=" + s },
		func(s string) string { return "redirect=/cb?token=" + s },
		func(s string) string { return "redirect=%2Fcb%3Ftoken%3D" + s },
		func(s string) string { return "redirect=%2Fcb%3FTOKEN%3D" + s + "&keep=1" },
		// No literal "=", so the pair has a name and no value.
		func(s string) string { return "x%3Ftoken%3D" + s },
		// The covered value is in the name, so masking only the value isn't enough.
		func(s string) string { return "x%3Ftoken%3D" + s + "=1" },
		// A name that can't be decoded can't be trusted either.
		func(s string) string { return "%zz%3Ftoken%3D" + s + "=1" },
		func(s string) string { return "%zz" + s },
	} {
		secret := sentinel(t)
		var hits Hits
		got := engine.Query(in(secret), &hits)
		assertAbsent(t, secret, got)
		if len(hits.List()) == 0 {
			t.Fatalf("no hit for %q", got)
		}
	}
	for _, unchanged := range []string{"note=tokens%20are%20fine", "token", "a=1&token&b=2"} {
		if got := engine.Query(unchanged, &Hits{}); got != unchanged {
			t.Fatalf("over-matched %q: %q", unchanged, got)
		}
	}
}

func TestQueryWithoutMatchesIsUnchanged(t *testing.T) {
	engine := newEngine(t, `query_params: [token]`)
	var hits Hits
	for _, q := range []string{"", "a=1&b=2", "a=hello%20world", "flag", "a=1&&b"} {
		if got := engine.Query(q, &hits); got != q {
			t.Errorf("Query(%q) = %q", q, got)
		}
	}
	if len(hits.List()) != 0 {
		t.Fatalf("hits = %+v", hits.List())
	}
}

func jsonInput(data string) BodyInput {
	return BodyInput{ContentType: "application/json", Data: []byte(data)}
}

func TestJSONBodyRedactsNestedFieldsInBothDirections(t *testing.T) {
	engine := newEngine(t, `json_paths: ["$.user.email", "$.items[*].card", "$..password"]`)
	secret := sentinel(t)
	doc := `{"user":{"email":"` + secret + `","id":7},"items":[{"card":"` + secret + `","sku":"a"}],"deep":{"x":[{"password":"` + secret + `"}]}}`
	for _, loc := range []Location{RequestBody, ResponseBody} {
		var hits Hits
		res := engine.Body(loc, jsonInput(doc), &hits)
		assertAbsent(t, secret, res)
		if res.Failed || res.Body.State != traffic.BodyPresent {
			t.Fatalf("%s: result = %+v", loc, res)
		}
		var got map[string]any
		if err := json.Unmarshal(res.Body.Data, &got); err != nil {
			t.Fatal(err)
		}
		if got["user"].(map[string]any)["id"] != float64(7) {
			t.Fatalf("%s: unrelated field lost: %s", loc, res.Body.Data)
		}
		if len(hits.List()) != 3 {
			t.Fatalf("%s: hits = %+v", loc, hits.List())
		}
	}
}

func TestHitsNameTheRuleNotTheData(t *testing.T) {
	engine := newEngine(t, `json_paths: ["$.*.email"]`)
	secret := sentinel(t)
	var hits Hits
	engine.Body(ResponseBody, jsonInput(`{"`+secret+`":{"email":"x"}}`), &hits)
	assertAbsent(t, secret, hits.List())
	if list := hits.List(); len(list) != 1 || list[0].Rule != "$.*.email" {
		t.Fatalf("hits = %+v", list)
	}
}

func TestJSONBodyPreservesWhatComparisonDependsOn(t *testing.T) {
	engine := newEngine(t, `json_paths: ["$.gone"]`)
	res := engine.Body(ResponseBody, jsonInput(`{"big":12345678901234567890,"exact":1.10,"nothing":null,"html":"<a&b>","list":[3,1,2]}`), &Hits{})
	if res.Failed {
		t.Fatalf("result = %+v", res)
	}
	got := string(res.Body.Data)
	for _, want := range []string{`"big":12345678901234567890`, `"exact":1.10`, `"nothing":null`, `"html":"<a&b>"`, `"list":[3,1,2]`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

// With duplicate keys, parsers disagree on which value counts. Storing the
// re-encoded tree means the value that was matched is the only one kept.
func TestDuplicateKeysCannotSmuggleAValuePastARule(t *testing.T) {
	engine := newEngine(t, `json_paths: ["$.email"]`)
	secret := sentinel(t)
	for _, doc := range []string{
		`{"email":"` + secret + `","email":"second"}`,
		`{"email":"first","email":"` + secret + `"}`,
		`{"email":"` + secret + `"}`,
		`{"EMAIL":"` + secret + `"}`,
	} {
		res := engine.Body(RequestBody, jsonInput(doc), &Hits{})
		assertAbsent(t, secret, res)
		if res.Body.State != traffic.BodyPresent {
			t.Fatalf("state = %s", res.Body.State)
		}
	}
}

func TestMalformedJSONIsOmittedAndFails(t *testing.T) {
	engine := newEngine(t, `json_paths: ["$.email"]`)
	secret := sentinel(t)
	for name, doc := range map[string]string{
		"truncated":      `{"email":"` + secret,
		"trailing data":  `{"email":"x"} ` + secret,
		"second value":   `{"email":"x"}{"email":"` + secret + `"}`,
		"not json":       secret,
		"unquoted value": `{"email":` + secret + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			res := engine.Body(RequestBody, jsonInput(doc), &Hits{})
			assertAbsent(t, secret, res)
			if !res.Failed || res.Body.State != traffic.BodyOmitted || res.Body.Reason != ReasonMalformedJSON {
				t.Fatalf("result = %+v", res)
			}
			if res.Body.Data != nil {
				t.Fatal("omitted body holds data")
			}
		})
	}
}

func TestStructuredSuffixAndParametersAreRecognized(t *testing.T) {
	engine := newEngine(t, `json_paths: ["$.email"]`)
	secret := sentinel(t)
	for _, contentType := range []string{"application/json; charset=utf-8", "application/problem+json", "APPLICATION/JSON"} {
		res := engine.Body(ResponseBody, BodyInput{ContentType: contentType, Data: []byte(`{"email":"` + secret + `"}`)}, &Hits{})
		assertAbsent(t, secret, res)
		if res.Body.State != traffic.BodyPresent {
			t.Fatalf("%s: state = %s", contentType, res.Body.State)
		}
	}
}

func TestEmptyBodyIsDistinctFromOmitted(t *testing.T) {
	engine := newEngine(t, "")
	for _, in := range []BodyInput{{}, {ContentType: "application/json"}, {ContentType: "application/octet-stream", Data: []byte{}}} {
		res := engine.Body(RequestBody, in, &Hits{})
		if res.Body.State != traffic.BodyEmpty || res.Failed {
			t.Fatalf("input %+v: result = %+v", in, res)
		}
	}
}

func TestFormBodyUsesQueryRules(t *testing.T) {
	engine := newEngine(t, `query_params: [password]`)
	secret := sentinel(t)
	res := engine.Body(RequestBody, BodyInput{ContentType: "application/x-www-form-urlencoded", Data: []byte("user=a&password=" + secret)}, &Hits{})
	assertAbsent(t, secret, res)
	if string(res.Body.Data) != "user=a&password=REDACTED" {
		t.Fatalf("data = %q", res.Body.Data)
	}
}

func compress(t *testing.T, encoding string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch encoding {
	case "gzip":
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case "deflate":
		w := zlib.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case "zstd":
		w, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestCompressedBodiesAreDecompressedThenRedacted(t *testing.T) {
	engine := newEngine(t, `json_paths: ["$.user.email"]`)
	for _, encoding := range []string{"gzip", "deflate", "zstd", "GZIP"} {
		t.Run(encoding, func(t *testing.T) {
			secret := sentinel(t)
			data := compress(t, strings.ToLower(encoding), []byte(`{"user":{"email":"`+secret+`","id":1}}`))
			res := engine.Body(ResponseBody, BodyInput{ContentType: "application/json", ContentEncoding: encoding, Data: data}, &Hits{})
			assertAbsent(t, secret, res)
			if res.Body.State != traffic.BodyPresent || res.Body.OriginalEncoding == "" {
				t.Fatalf("result = %+v", res)
			}
			if !strings.Contains(string(res.Body.Data), `"id":1`) {
				t.Fatalf("data = %s", res.Body.Data)
			}
		})
	}
}

func TestCompressedMalformedJSONIsOmitted(t *testing.T) {
	engine := newEngine(t, "")
	secret := sentinel(t)
	data := compress(t, "gzip", []byte(`{"email":"`+secret))
	res := engine.Body(ResponseBody, BodyInput{ContentType: "application/json", ContentEncoding: "gzip", Data: data}, &Hits{})
	assertAbsent(t, secret, res)
	if !res.Failed || res.Body.Reason != ReasonMalformedJSON {
		t.Fatalf("result = %+v", res)
	}
}

func TestBodiesThatCannotBeDecompressedAreOmitted(t *testing.T) {
	engine := newEngine(t, "")
	secret := sentinel(t)
	tests := []struct {
		name     string
		encoding string
		data     []byte
		reason   string
	}{
		{"not gzip", "gzip", []byte(`{"email":"` + secret + `"}`), ReasonMalformedCompression},
		{"not deflate", "deflate", []byte(secret), ReasonMalformedCompression},
		{"not zstd", "zstd", []byte(secret), ReasonMalformedCompression},
		{"truncated gzip", "gzip", compress(t, "gzip", []byte(secret+secret))[:20], ReasonMalformedCompression},
		{"gzip with trailing junk", "gzip", append(compress(t, "gzip", []byte(`{}`)), []byte(secret)...), ReasonMalformedCompression},
		{"unsupported", "br", []byte(secret), ReasonUnsupportedEncoding},
		{"stacked", "gzip, gzip", compress(t, "gzip", compress(t, "gzip", []byte(secret))), ReasonUnsupportedEncoding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := engine.Body(ResponseBody, BodyInput{ContentType: "application/json", ContentEncoding: tt.encoding, Data: tt.data}, &Hits{})
			assertAbsent(t, secret, res)
			if !res.Failed || res.Body.State != traffic.BodyOmitted || res.Body.Reason != tt.reason {
				t.Fatalf("result = %+v", res)
			}
		})
	}
}

func TestDecompressionIsBounded(t *testing.T) {
	policy, err := ParsePolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(policy, Options{MaxDecompressedBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	bomb := []byte(`{"a":"` + strings.Repeat("A", 1<<20) + `"}`)
	for _, encoding := range []string{"gzip", "deflate", "zstd"} {
		res := engine.Body(ResponseBody, BodyInput{ContentType: "application/json", ContentEncoding: encoding, Data: compress(t, encoding, bomb)}, &Hits{})
		if !res.Failed || res.Body.State != traffic.BodyOmitted || res.Body.Reason != ReasonDecompressedTooLarge {
			t.Errorf("%s: result = %+v", encoding, res)
		}
	}
}

func TestContentTypesWithoutRulesAreOmitted(t *testing.T) {
	engine := newEngine(t, "")
	secret := sentinel(t)
	for _, contentType := range []string{"", "text/plain", "text/html; charset=utf-8", "application/octet-stream", "multipart/form-data; boundary=x", "application/grpc", "not/a type;;"} {
		res := engine.Body(ResponseBody, BodyInput{ContentType: contentType, Data: []byte(secret)}, &Hits{})
		assertAbsent(t, secret, res)
		if res.Body.State != traffic.BodyOmitted || res.Body.Reason != ReasonUnsupportedContentType {
			t.Errorf("%q: result = %+v", contentType, res)
		}
		if res.Failed {
			t.Errorf("%q: having no rules isn't a redaction failure", contentType)
		}
	}
}

func TestOpaqueContentTypesAreStoredOnlyWhenListed(t *testing.T) {
	engine := newEngine(t, `opaque_content_types: [text/plain]`)
	res := engine.Body(ResponseBody, BodyInput{ContentType: "text/plain; charset=utf-8", Data: []byte("hello")}, &Hits{})
	if res.Body.State != traffic.BodyPresent || string(res.Body.Data) != "hello" {
		t.Fatalf("result = %+v", res)
	}
	res = engine.Body(ResponseBody, BodyInput{ContentType: "text/html", Data: []byte("hello")}, &Hits{})
	if res.Body.State != traffic.BodyOmitted {
		t.Fatalf("result = %+v", res)
	}
}

func TestContentTypeRecordsOnlyTheMediaType(t *testing.T) {
	engine := newEngine(t, "")
	res := engine.Body(ResponseBody, BodyInput{ContentType: "application/json; charset=utf-8", Data: []byte("{}")}, &Hits{})
	if res.Body.ContentType != "application/json" {
		t.Fatalf("content type = %q", res.Body.ContentType)
	}
}

func TestSessionKeyIsADigestOfTheConfiguredSource(t *testing.T) {
	engine := newEngine(t, `session: {sources: ["cookie:sid"]}`)
	secret := sentinel(t)
	header := http.Header{"Cookie": {"other=1; sid=" + secret}}
	key := engine.SessionKey(header, "")
	assertAbsent(t, secret, key)
	if key == "" || len(key) > traffic.MaxSessionKeyBytes {
		t.Fatalf("key = %q", key)
	}
	if engine.SessionKey(header, "") != key {
		t.Fatal("key isn't stable within an engine")
	}
	if engine.SessionKey(http.Header{"Cookie": {"sid=different"}}, "") == key {
		t.Fatal("different sessions share a key")
	}
}

func TestSessionKeyDependsOnTheSecret(t *testing.T) {
	policy, err := ParsePolicy([]byte(`session: {sources: ["header:X-Session"]}`))
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{"X-Session": {"s1"}}
	keyWith := func(secret []byte) string {
		engine, err := NewEngine(policy, Options{SessionSecret: secret})
		if err != nil {
			t.Fatal(err)
		}
		defer engine.Close()
		return engine.SessionKey(header, "")
	}
	first, again := keyWith([]byte("one")), keyWith([]byte("one"))
	if first != again {
		t.Fatal("a shared secret must correlate across engines")
	}
	if first == keyWith([]byte("two")) {
		t.Fatal("different secrets must not correlate")
	}
	generatedA, generatedB := keyWith(nil), keyWith(nil)
	if generatedA == generatedB {
		t.Fatal("generated secrets must differ, so correlation ends with the run")
	}
}

func TestSessionSourcesAreTriedInOrder(t *testing.T) {
	engine := newEngine(t, `session: {sources: ["cookie:sid", "header:X-Session", "query:session"]}`)
	fromQuery := engine.SessionKey(http.Header{}, "session=abc")
	fromHeader := engine.SessionKey(http.Header{"X-Session": {"abc"}}, "session=abc")
	fromCookie := engine.SessionKey(http.Header{"Cookie": {"sid=abc"}, "X-Session": {"abc"}}, "session=abc")
	if fromQuery == "" || fromHeader == "" || fromCookie == "" {
		t.Fatalf("keys: %q %q %q", fromQuery, fromHeader, fromCookie)
	}
	// The same value under a different source is a different identity.
	if fromQuery == fromHeader || fromHeader == fromCookie {
		t.Fatalf("sources aren't separated: %q %q %q", fromQuery, fromHeader, fromCookie)
	}
}

func TestNoSessionSourceMeansNoSessionKey(t *testing.T) {
	engine := newEngine(t, `session: {sources: ["cookie:sid"]}`)
	if key := engine.SessionKey(http.Header{}, ""); key != "" {
		t.Fatalf("key = %q", key)
	}
	unconfigured := newEngine(t, "")
	if key := unconfigured.SessionKey(http.Header{"Cookie": {"sid=a"}}, ""); key != "" {
		t.Fatalf("key = %q", key)
	}
}

func TestEngineIsSafeForConcurrentUse(t *testing.T) {
	engine := newEngine(t, `json_paths: ["$.a"]`)
	inputs := make([][]byte, 50)
	for i := range inputs {
		inputs[i] = compress(t, "zstd", []byte(`{"a":`+strconv.Itoa(i)+`}`))
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for _, data := range inputs {
				res := engine.Body(ResponseBody, BodyInput{ContentType: "application/json", ContentEncoding: "zstd", Data: data}, &Hits{})
				if res.Body.State != traffic.BodyPresent {
					t.Errorf("result = %+v", res)
				}
			}
		})
	}
	wg.Wait()
}

// Binary metadata is opaque, and grpc-message is free text that servers fill with whatever
// went wrong. Neither can be checked against rules, so neither is kept.
func TestGRPCMetadataThatCouldHoldAnythingIsMasked(t *testing.T) {
	engine := newEngine(t, "")
	secret := sentinel(t)
	got := engine.Headers(ResponseTrailer, http.Header{
		"Grpc-Status":             {"5"},
		"Grpc-Message":            {"order for " + secret + " not found"},
		"Grpc-Status-Details-Bin": {secret},
		"X-Trace-Bin":             {secret},
		"Grpc-Encoding":           {"gzip"},
		"Grpc-Accept-Encoding":    {"gzip"},
	}, &Hits{})
	assertAbsent(t, secret, got)
	if !reflect.DeepEqual(got["Grpc-Status"], []string{"5"}) {
		t.Fatalf("status must be kept: %v", got)
	}
	for _, name := range []string{"Grpc-Message", "Grpc-Status-Details-Bin", "X-Trace-Bin"} {
		if !reflect.DeepEqual(got[name], []string{Placeholder}) {
			t.Errorf("%s = %v", name, got[name])
		}
	}
	for _, name := range []string{"Grpc-Encoding", "Grpc-Accept-Encoding"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s describes the original bytes and must not be stored", name)
		}
	}
}
