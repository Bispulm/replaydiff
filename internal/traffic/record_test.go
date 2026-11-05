package traffic

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validRecord() *Record {
	return &Record{
		SchemaVersion: SchemaVersion,
		ID:            "01JC0000000000000000000000",
		Seq:           1,
		CapturedAt:    time.Date(2026, 11, 5, 15, 4, 5, 0, time.UTC),
		SessionKey:    strings.Repeat("ab", 8),
		Protocol:      ProtocolHTTP11,
		Request: Request{
			Method:   "GET",
			Path:     "/v1/orders/ord-1",
			RawQuery: "a=1",
			Headers:  map[string][]string{"Accept": {"application/json"}},
			Body:     Body{State: BodyEmpty},
		},
		Response: &Response{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
			Body:       Body{State: BodyPresent, ContentType: "application/json", Data: []byte(`{"ok":true}`)},
		},
		Timing:    Timing{HeadersMicros: 100, TotalMicros: 200},
		Outcome:   Outcome{Transport: TransportOK},
		Redaction: Redaction{Complete: true},
		Replay:    ReplayInfo{Eligible: true},
	}
}

func TestRecordRoundTripsThroughJSON(t *testing.T) {
	rec := validRecord()
	status := 5
	rec.Response.GRPCStatus = &status
	rec.Redaction.Hits = []RedactionHit{{Location: "response.body", Rule: "$.user.email", Count: 2}}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var got Record
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rec, &got) {
		t.Fatalf("round trip mismatch:\nwant %+v\ngot  %+v", rec, &got)
	}
}

func TestBodyStatesStayDistinctAfterEncoding(t *testing.T) {
	states := []Body{
		{State: BodyEmpty},
		{State: BodyOmitted, Reason: "malformed_json"},
		{State: BodyTruncated, Reason: "upstream_aborted"},
		{State: BodyUnavailable, Reason: "no_response"},
	}
	for _, in := range states {
		data, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var out Body
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		if out.State != in.State {
			t.Errorf("state %q decoded as %q", in.State, out.State)
		}
		if out.Data != nil {
			t.Errorf("state %q decoded with data", in.State)
		}
	}
}

func TestStatusAndGRPCStatusAreSeparateFields(t *testing.T) {
	rec := validRecord()
	data, err := json.Marshal(rec.Response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "grpc_status") {
		t.Fatalf("HTTP response must omit grpc_status: %s", data)
	}
	zero := 0
	rec.Response.GRPCStatus = &zero
	data, err = json.Marshal(rec.Response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"grpc_status":0`) {
		t.Fatalf("gRPC OK must be distinct from absent: %s", data)
	}
}

func TestValidateAcceptsValidRecord(t *testing.T) {
	if err := validRecord().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAcceptsRecordWithoutResponse(t *testing.T) {
	rec := validRecord()
	rec.Response = nil
	rec.Outcome = Outcome{Transport: TransportUpstreamError}
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsUntrustedInput(t *testing.T) {
	tests := map[string]func(*Record){
		"wrong schema version":     func(r *Record) { r.SchemaVersion = 2 },
		"missing id":               func(r *Record) { r.ID = "" },
		"id with path characters":  func(r *Record) { r.ID = "../../etc/passwd" },
		"oversized id":             func(r *Record) { r.ID = strings.Repeat("a", 65) },
		"zero sequence":            func(r *Record) { r.Seq = 0 },
		"zero capture time":        func(r *Record) { r.CapturedAt = time.Time{} },
		"non-hex session key":      func(r *Record) { r.SessionKey = "not hex!" },
		"oversized session key":    func(r *Record) { r.SessionKey = strings.Repeat("a", 129) },
		"unknown protocol":         func(r *Record) { r.Protocol = "ftp" },
		"relative rpc":             func(r *Record) { r.RPC = "pkg.Svc/Method" },
		"rpc with newline":         func(r *Record) { r.RPC = "/a\nb" },
		"descriptor not hex":       func(r *Record) { r.Descriptor = &DescriptorRef{SetDigest: "not hex"} },
		"empty method":             func(r *Record) { r.Request.Method = "" },
		"method with space":        func(r *Record) { r.Request.Method = "GET /x" },
		"oversized method":         func(r *Record) { r.Request.Method = strings.Repeat("A", 33) },
		"absolute url path":        func(r *Record) { r.Request.Path = "http://evil.example/" },
		"relative path":            func(r *Record) { r.Request.Path = "orders" },
		"path with newline":        func(r *Record) { r.Request.Path = "/a\r\nHost: evil" },
		"oversized path":           func(r *Record) { r.Request.Path = "/" + strings.Repeat("a", MaxPathBytes) },
		"query with control char":  func(r *Record) { r.Request.RawQuery = "a=\x00" },
		"oversized query":          func(r *Record) { r.Request.RawQuery = strings.Repeat("a", MaxQueryBytes+1) },
		"invalid header name":      func(r *Record) { r.Request.Headers = map[string][]string{"Bad Name": {"x"}} },
		"header value with CRLF":   func(r *Record) { r.Request.Headers = map[string][]string{"X-A": {"a\r\nX-B: c"}} },
		"too many headers":         func(r *Record) { r.Request.Headers = manyHeaders(MaxHeaders + 1) },
		"invalid trailer name":     func(r *Record) { r.Response.Trailers = map[string][]string{"Bad Name": {"x"}} },
		"status below range":       func(r *Record) { r.Response.StatusCode = 99 },
		"status above range":       func(r *Record) { r.Response.StatusCode = 1000 },
		"grpc status out of range": func(r *Record) { s := 256; r.Response.GRPCStatus = &s },
		"unknown body state":       func(r *Record) { r.Request.Body.State = "secret" },
		"missing body state":       func(r *Record) { r.Request.Body = Body{} },
		"data in omitted body": func(r *Record) {
			r.Request.Body = Body{State: BodyOmitted, Reason: "x", Data: []byte("raw")}
		},
		"data in truncated body": func(r *Record) {
			r.Response.Body = Body{State: BodyTruncated, Data: []byte("raw")}
		},
		"data in empty body": func(r *Record) {
			r.Request.Body = Body{State: BodyEmpty, Data: []byte("raw")}
		},
		"present body without data": func(r *Record) { r.Request.Body = Body{State: BodyPresent} },
		"negative observed bytes":   func(r *Record) { r.Request.Body.ObservedBytes = -1 },
		"negative timing":           func(r *Record) { r.Timing.TotalMicros = -1 },
		"unknown transport outcome": func(r *Record) { r.Outcome.Transport = "exploded" },
		"negative redaction count": func(r *Record) {
			r.Redaction.Hits = []RedactionHit{{Location: "x", Rule: "y", Count: -1}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			rec := validRecord()
			mutate(rec)
			if err := rec.Validate(); err == nil {
				t.Fatal("want validation error")
			}
		})
	}
}

func manyHeaders(n int) map[string][]string {
	out := make(map[string][]string, n)
	for i := range n {
		out["X-H"+strings.Repeat("a", i%50)+string(rune('a'+i%26))+strings.Repeat("b", i/26)] = []string{"v"}
	}
	return out
}

func TestOptionsAsteriskPathIsAccepted(t *testing.T) {
	rec := validRecord()
	rec.Request.Method = "OPTIONS"
	rec.Request.Path = "*"
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidationErrorsDoNotQuoteContent(t *testing.T) {
	const sentinel = "sentinel-value-in-path"
	rec := validRecord()
	rec.Request.Path = "relative/" + sentinel
	err := rec.Validate()
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error quotes content: %v", err)
	}
}

func TestNewIDIsValidUniqueAndTimeOrdered(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	seen := make(map[string]bool)
	for range 1000 {
		id := NewID(early)
		if !isIdentifier(id, MaxIDBytes) || len(id) != 26 {
			t.Fatalf("id = %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
		if id >= NewID(late) {
			t.Fatalf("ids aren't time ordered: %q", id)
		}
	}
}
