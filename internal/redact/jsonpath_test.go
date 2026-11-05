package redact

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func decodeJSON(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestParseJSONPathRejectsUnsupportedSyntax(t *testing.T) {
	for _, path := range []string{
		"",
		"user.email",
		"$.",
		"$..",
		"$..*",
		"$.user..",
		"$.a b",
		"$[",
		"$[]",
		"$[-1]",
		"$[1:2]",
		"$[?(@.a)]",
		"$['unterminated",
		"$['a']b",
		"$.user[",
		"$.a.",
		"$*",
	} {
		if _, err := parseJSONPath(path); err == nil {
			t.Errorf("parseJSONPath(%q): want error", path)
		}
	}
}

func TestApplyJSONPath(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		in    string
		want  string
		count int
	}{
		{"root", "$", `{"a":1}`, `"[REDACTED]"`, 1},
		{"key", "$.a", `{"a":1,"b":2}`, `{"a":"[REDACTED]","b":2}`, 1},
		{"nested", "$.a.b", `{"a":{"b":1,"c":2}}`, `{"a":{"b":"[REDACTED]","c":2}}`, 1},
		{"whole subtree", "$.a", `{"a":{"b":{"c":1}}}`, `{"a":"[REDACTED]"}`, 1},
		{"quoted key", "$['a.b']", `{"a.b":1,"a":{"b":2}}`, `{"a.b":"[REDACTED]","a":{"b":2}}`, 1},
		{"key case differs", "$.email", `{"EMAIL":"x","Email":"y"}`, `{"EMAIL":"[REDACTED]","Email":"[REDACTED]"}`, 2},
		{"index", "$.a[1]", `{"a":[1,2,3]}`, `{"a":[1,"[REDACTED]",3]}`, 1},
		{"index out of range", "$.a[9]", `{"a":[1]}`, `{"a":[1]}`, 0},
		{"array wildcard", "$.a[*].b", `{"a":[{"b":1},{"b":2},{"c":3}]}`, `{"a":[{"b":"[REDACTED]"},{"b":"[REDACTED]"},{"c":3}]}`, 2},
		{"member wildcard", "$.a.*", `{"a":{"x":1,"y":2}}`, `{"a":{"x":"[REDACTED]","y":"[REDACTED]"}}`, 2},
		{"wildcard over array", "$.*", `[1,2]`, `["[REDACTED]","[REDACTED]"]`, 2},
		{"recursive", "$..secret", `{"secret":1,"a":{"secret":2,"b":[{"secret":3}]}}`, `{"secret":"[REDACTED]","a":{"secret":"[REDACTED]","b":[{"secret":"[REDACTED]"}]}}`, 3},
		{"recursive then key", "$..a.b", `{"a":{"b":1},"c":{"a":{"b":2}}}`, `{"a":{"b":"[REDACTED]"},"c":{"a":{"b":"[REDACTED]"}}}`, 2},
		{"recursive inside match", "$..a.b", `{"a":{"a":{"b":1}}}`, `{"a":{"a":{"b":"[REDACTED]"}}}`, 1},
		{"no match", "$.x", `{"a":1}`, `{"a":1}`, 0},
		{"type mismatch", "$.a.b", `{"a":"text"}`, `{"a":"text"}`, 0},
		{"null value", "$.a", `{"a":null}`, `{"a":"[REDACTED]"}`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := parseJSONPath(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			got, count := path.apply(decodeJSON(t, tt.in))
			if !reflect.DeepEqual(got, decodeJSON(t, tt.want)) {
				t.Fatalf("got %v, want %s", got, tt.want)
			}
			if count != tt.count {
				t.Fatalf("count = %d, want %d", count, tt.count)
			}
		})
	}
}
