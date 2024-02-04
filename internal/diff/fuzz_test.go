package diff

import (
	"encoding/json"
	"testing"

	"github.com/Bispulm/replaydiff/internal/redact"
)

// FuzzCompare feeds arbitrary responses from three targets. Whatever they send, the
// comparator must not panic, and when all three send the same body nothing may be
// reported as a change.
func FuzzCompare(f *testing.F) {
	f.Add([]byte(`{"a":1}`), []byte(`{"a":2}`), []byte(`{"b":[1,{"c":null}]}`), "application/json")
	f.Add([]byte(`[1,2,3]`), []byte(`[1,2]`), []byte(`[]`), "application/json")
	f.Add([]byte(`{"a":1e999999}`), []byte(`{"a":1.0}`), []byte(`{"a":1}`), "application/problem+json")
	f.Add([]byte(`{"a":`), []byte(`null`), []byte(``), "application/json")
	f.Add([]byte(`plain`), []byte(`text`), []byte(`here`), "text/plain")

	policy, err := redact.ParsePolicy([]byte(`opaque_content_types: [text/plain]`))
	if err != nil {
		f.Fatal(err)
	}
	engine, err := redact.NewEngine(policy, redact.Options{})
	if err != nil {
		f.Fatal(err)
	}
	defer engine.Close()
	cfg, err := ParseConfig(nil)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, a, b, c []byte, contentType string) {
		comparator, err := New(cfg, engine)
		if err != nil {
			t.Fatal(err)
		}
		reply := func(body []byte) reply { return reply{status: 200, contentType: contentType, body: string(body)} }
		comparator.Observe(record(1, "GET", "/x", reply(a), reply(b), reply(c)))
		if _, err := json.Marshal(comparator.Result()); err != nil {
			t.Fatalf("result doesn't encode: %v", err)
		}

		same, err := New(cfg, engine)
		if err != nil {
			t.Fatal(err)
		}
		same.Observe(record(1, "GET", "/x", reply(a), reply(a), reply(a)))
		for _, finding := range same.Result().Findings {
			switch finding.Severity {
			case SeverityBreaking, SeverityWarning:
				t.Fatalf("identical responses reported as a change: %+v", finding)
			case SeverityUncertain, SeverityInfo:
			}
		}
	})
}
