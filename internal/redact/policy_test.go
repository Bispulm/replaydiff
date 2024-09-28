package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePolicyAcceptsDocumentedFields(t *testing.T) {
	p, err := ParsePolicy([]byte(`
headers: [X-Internal]
query_params: [token]
json_paths: ["$.user.email", "$..password"]
opaque_content_types: [text/plain]
session:
  sources: ["cookie:sid", "header:X-Session", "query:session"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.JSONPaths) != 2 || len(p.Session.Sources) != 3 || len(p.Headers) != 1 {
		t.Fatalf("policy = %+v", p)
	}
}

// A misspelled key must stop startup. Ignoring it would silently turn off the
// redaction the operator believes is active.
func TestParsePolicyRejectsUnknownKeys(t *testing.T) {
	for _, doc := range []string{
		"json_path: [\"$.a\"]",
		"Headers: [X-A]",
		"session: {source: [\"cookie:a\"]}",
	} {
		if _, err := ParsePolicy([]byte(doc)); err == nil {
			t.Errorf("ParsePolicy(%q): want error", doc)
		}
	}
}

func TestParsePolicyRejectsInvalidRules(t *testing.T) {
	for name, doc := range map[string]string{
		"bad json path":       `json_paths: ["user.email"]`,
		"bad session source":  `session: {sources: ["form:a"]}`,
		"empty session name":  `session: {sources: ["cookie:"]}`,
		"empty header":        `headers: [""]`,
		"empty query param":   `query_params: [""]`,
		"bad opaque type":     `opaque_content_types: ["not a type"]`,
		"json as opaque type": `opaque_content_types: ["application/json"]`,
		"wrong field type":    `headers: "X-A"`,
		"multiple documents":  "headers: [X-A]\n---\nheaders: [X-B]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicy([]byte(doc)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

// Protobuf rules can't be honored until descriptor support exists. Accepting
// them now would claim protection that isn't there.
func TestParsePolicyRefusesProtoFieldsUntilSupported(t *testing.T) {
	_, err := ParsePolicy([]byte(`proto_fields: ["orders.v1.Customer.email"]`))
	if err == nil || !strings.Contains(err.Error(), "proto_fields") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptyPolicyIsValid(t *testing.T) {
	if _, err := ParsePolicy(nil); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPolicyFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redact.yaml")
	if err := os.WriteFile(path, []byte(`query_params: [token]`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.QueryParams) != 1 {
		t.Fatalf("policy = %+v", p)
	}
	if _, err := LoadPolicy(path + ".absent"); err == nil {
		t.Fatal("want error for a missing file")
	}
}

func TestPolicyDigestChangesWithRules(t *testing.T) {
	a, err := ParsePolicy([]byte(`query_params: [token]`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParsePolicy([]byte(`query_params: [token, key]`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() == "" || a.Digest() == b.Digest() {
		t.Fatalf("digests %q and %q", a.Digest(), b.Digest())
	}
}
