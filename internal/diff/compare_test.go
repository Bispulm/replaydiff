package diff

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/replay"
)

const jsonType = "application/json"

// reply is one target's response to a record.
type reply struct {
	status      int
	contentType string
	encoding    string
	body        string
	outcome     replay.CallOutcome
	latency     int64
	header      http.Header
}

func jsonReply(body string) reply { return reply{status: 200, contentType: jsonType, body: body} }

func record(seq int, method, path string, a, b, c reply) *replay.RecordResult {
	result := &replay.RecordResult{ID: fmt.Sprintf("rec-%04d", seq), Seq: uint64(seq), Method: method, Path: path}
	for i, r := range []reply{a, b, c} {
		call := replay.CallResult{
			Role:          replay.Role(i).String(),
			Outcome:       r.outcome,
			Status:        r.status,
			LatencyMicros: r.latency,
			Header:        http.Header{},
			Body:          []byte(r.body),
		}
		if call.Outcome == "" {
			call.Outcome = replay.CallOK
		}
		if r.contentType != "" {
			call.Header.Set("Content-Type", r.contentType)
		}
		if r.encoding != "" {
			call.Header.Set("Content-Encoding", r.encoding)
		}
		for name, values := range r.header {
			call.Header[name] = values
		}
		result.Calls[i] = call
	}
	return result
}

func newComparator(t *testing.T, config, policy string) *Comparator {
	t.Helper()
	cfg, err := ParseConfig([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	p, err := redact.ParsePolicy([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redact.NewEngine(p, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	comparator, err := New(cfg, engine)
	if err != nil {
		t.Fatal(err)
	}
	return comparator
}

// compareOne runs one record through a default comparator.
func compareOne(t *testing.T, a, b, c reply) *Result {
	t.Helper()
	comparator := newComparator(t, "", "")
	comparator.Observe(record(1, "GET", "/x", a, b, c))
	return comparator.Result()
}

func kinds(result *Result) []string {
	out := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		out = append(out, string(f.Severity)+":"+string(f.Kind)+":"+f.Path)
	}
	slices.Sort(out)
	return out
}

func wantKinds(t *testing.T, result *Result, want ...string) {
	t.Helper()
	slices.Sort(want)
	got := kinds(result)
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n got  %v\n want %v", got, want)
	}
}

func TestIdenticalResponsesProduceNoFindings(t *testing.T) {
	same := jsonReply(`{"a":1,"b":{"c":[1,2,{"d":null}]},"e":"text","f":true}`)
	wantKinds(t, compareOne(t, same, same, same))
}

func TestStatusChanges(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b, c int
		want    []string
	}{
		"same":                {200, 200, 200, nil},
		"class changed":       {200, 200, 500, []string{"breaking:status_class_changed:"}},
		"404 becomes 500":     {404, 404, 500, []string{"breaking:status_class_changed:"}},
		"code changed":        {200, 200, 201, []string{"warning:status_changed:"}},
		"baselines disagree":  {200, 404, 200, []string{"uncertain:baseline_status_unstable:"}},
		"outside both":        {200, 404, 500, []string{"uncertain:baseline_status_unstable:", "breaking:status_class_changed:"}},
		"disagree same class": {200, 201, 204, []string{"uncertain:baseline_status_unstable:"}},
	} {
		t.Run(name, func(t *testing.T) {
			r := func(status int) reply { return reply{status: status, contentType: jsonType, body: `{}`} }
			wantKinds(t, compareOne(t, r(tc.a), r(tc.b), r(tc.c)), tc.want...)
		})
	}
}

func TestCandidateCallFailureIsBreakingAndBaselineFailureIsNotCompared(t *testing.T) {
	ok := jsonReply(`{}`)
	failed := reply{outcome: replay.CallTimeout}
	wantKinds(t, compareOne(t, ok, ok, failed), "breaking:candidate_call_failed:")

	result := compareOne(t, failed, ok, ok)
	wantKinds(t, result)
	if result.Coverage.NotCompared["baseline_failed"] != 1 || result.Coverage.Compared != 0 {
		t.Fatalf("coverage = %+v", result.Coverage)
	}
}

func TestJSONComparison(t *testing.T) {
	for name, tc := range map[string]struct {
		base, candidate string
		want            []string
	}{
		"key order ignored":      {`{"a":1,"b":2}`, `{"b":2,"a":1}`, nil},
		"whitespace ignored":     {`{"a":1}`, `{ "a" : 1 }`, nil},
		"value changed":          {`{"a":1}`, `{"a":2}`, []string{"warning:value_changed:$.a"}},
		"precision kept":         {`{"a":12345678901234567890}`, `{"a":12345678901234567891}`, []string{"warning:value_changed:$.a"}},
		"small float difference": {`{"a":0.1000000000000000001}`, `{"a":0.1000000000000000002}`, []string{"warning:value_changed:$.a"}},
		"same number new format": {`{"a":1.0}`, `{"a":1}`, []string{"info:number_format_changed:$.a"}},
		"exponent same number":   {`{"a":1e2}`, `{"a":100}`, []string{"info:number_format_changed:$.a"}},
		"huge exponents":         {`{"a":1e999999999}`, `{"a":1e999999998}`, []string{"warning:value_changed:$.a"}},
		"field removed":          {`{"a":1,"b":2}`, `{"a":1}`, []string{"breaking:field_removed:$.b"}},
		"field added":            {`{"a":1}`, `{"a":1,"b":2}`, []string{"info:field_added:$.b"}},
		"null then missing":      {`{"a":null}`, `{}`, []string{"breaking:field_removed:$.a"}},
		"missing then null":      {`{}`, `{"a":null}`, []string{"info:field_added:$.a"}},
		"value then null":        {`{"a":1}`, `{"a":null}`, []string{"breaking:type_changed:$.a"}},
		"null then value":        {`{"a":null}`, `{"a":1}`, []string{"breaking:type_changed:$.a"}},
		"number to string":       {`{"a":1}`, `{"a":"1"}`, []string{"breaking:type_changed:$.a"}},
		"bool to string":         {`{"a":true}`, `{"a":"true"}`, []string{"breaking:type_changed:$.a"}},
		"object to array":        {`{"a":{}}`, `{"a":[]}`, []string{"breaking:type_changed:$.a"}},
		"root type changed":      {`{"a":1}`, `[1]`, []string{"breaking:type_changed:$"}},
		"nested removal":         {`{"a":{"b":{"c":1,"d":2}}}`, `{"a":{"b":{"c":1}}}`, []string{"breaking:field_removed:$.a.b.d"}},
		"subtree counted once":   {`{"a":{"b":1,"c":2}}`, `{}`, []string{"breaking:field_removed:$.a"}},
		"array order matters":    {`{"a":[1,2]}`, `{"a":[2,1]}`, []string{"warning:value_changed:$.a[*]"}},
		"array grew":             {`{"a":[1]}`, `{"a":[1,2]}`, []string{"warning:array_length_changed:$.a"}},
		"array shrank":           {`{"a":[1,2]}`, `{"a":[1]}`, []string{"warning:array_length_changed:$.a"}},
		"element field removed":  {`{"a":[{"x":1},{"x":2}]}`, `{"a":[{"x":1},{}]}`, []string{"breaking:field_removed:$.a[*].x"}},
		"element type changed":   {`{"a":[{"x":1}]}`, `{"a":[{"x":"1"}]}`, []string{"breaking:type_changed:$.a[*].x"}},
		"odd key names":          {`{"a b":{"c.d":1}}`, `{"a b":{"c.d":2}}`, []string{"warning:value_changed:$['a b']['c.d']"}},
	} {
		t.Run(name, func(t *testing.T) {
			wantKinds(t, compareOne(t, jsonReply(tc.base), jsonReply(tc.base), jsonReply(tc.candidate)), tc.want...)
		})
	}
}

func TestUnorderedArrayRule(t *testing.T) {
	comparator := newComparator(t, `unordered_arrays: [{route: "GET /x", paths: ["$.a"]}]`, "")
	comparator.Observe(record(1, "GET", "/x",
		jsonReply(`{"a":[{"n":1},{"n":2}],"b":[1,2]}`),
		jsonReply(`{"a":[{"n":2},{"n":1}],"b":[1,2]}`),
		jsonReply(`{"a":[{"n":2},{"n":1}],"b":[2,1]}`)))
	wantKinds(t, comparator.Result(), "warning:value_changed:$.b[*]")
}

func TestUnorderedArrayStillNoticesAChangedElement(t *testing.T) {
	comparator := newComparator(t, `unordered_arrays: [{route: "GET /x", paths: ["$.a"]}]`, "")
	comparator.Observe(record(1, "GET", "/x", jsonReply(`{"a":[1,2]}`), jsonReply(`{"a":[2,1]}`), jsonReply(`{"a":[1,3]}`)))
	wantKinds(t, comparator.Result(), "warning:value_changed:$.a[*]")
}

// noisy returns a record where field "t" differs on every target, as a timestamp does.
func noisy(seq int, path, extraBase, extraCandidate string) *replay.RecordResult {
	body := func(v int, extra string) reply {
		return jsonReply(fmt.Sprintf(`{"t":%d%s}`, seq*10+v, extra))
	}
	return record(seq, "GET", path, body(1, extraBase), body(2, extraBase), body(3, extraCandidate))
}

func TestBaselineDisagreementIsExplainedAsNoiseWhenEvidenceIsSufficient(t *testing.T) {
	comparator := newComparator(t, "", "")
	for seq := 1; seq <= 3; seq++ {
		comparator.Observe(noisy(seq, "/x", "", ""))
	}
	result := comparator.Result()
	wantKinds(t, result, "info:noise_explained:$.t")
	if len(result.Noise) != 1 {
		t.Fatalf("noise = %+v", result.Noise)
	}
	decision := result.Noise[0]
	if decision.Route != "GET /x" || decision.Path != "$.t" || decision.Type != "number" || decision.Decision != NoiseExplained ||
		decision.Observations != 3 || decision.BaselineDisagreements != 3 || decision.BaselineRate != 1 || decision.CandidateRate != 1 {
		t.Fatalf("decision = %+v", decision)
	}
}

// Too few observations can't tell noise from a real change. Saying so isn't a pass.
func TestTooFewObservationsAreUncertainRatherThanNoise(t *testing.T) {
	comparator := newComparator(t, "", "")
	comparator.Observe(noisy(1, "/x", "", ""))
	comparator.Observe(noisy(2, "/x", "", ""))
	result := comparator.Result()
	wantKinds(t, result, "uncertain:insufficient_baseline_evidence:$.t")
	if result.Noise[0].Decision != NoiseInsufficient {
		t.Fatalf("noise = %+v", result.Noise)
	}
}

func TestCandidateOnlyStructuralChangesAreBreakingOnNoisyFields(t *testing.T) {
	for name, tc := range map[string]struct {
		candidate func(seq int) string
		want      string
	}{
		"removed":     {func(int) string { return `{"other":1}` }, "breaking:field_removed:$.t"},
		"type change": {func(seq int) string { return fmt.Sprintf(`{"t":"%d"}`, seq) }, "breaking:type_changed:$.t"},
	} {
		t.Run(name, func(t *testing.T) {
			comparator := newComparator(t, "", "")
			for seq := 1; seq <= 5; seq++ {
				comparator.Observe(record(seq, "GET", "/x",
					jsonReply(fmt.Sprintf(`{"t":%d}`, seq*10+1)),
					jsonReply(fmt.Sprintf(`{"t":%d}`, seq*10+2)),
					jsonReply(tc.candidate(seq))))
			}
			got := kinds(comparator.Result())
			if !slices.Contains(got, tc.want) {
				t.Fatalf("findings = %v, want %s", got, tc.want)
			}
		})
	}
}

// A field that rarely varies between baselines doesn't excuse a candidate that always
// differs. Otherwise one flaky observation would hide a real change.
func TestCandidateDifferingFarMoreThanBaselinesIsAWarning(t *testing.T) {
	comparator := newComparator(t, "", "")
	for seq := 1; seq <= 10; seq++ {
		b := `{"v":"stable"}`
		if seq == 1 {
			b = `{"v":"blip"}`
		}
		comparator.Observe(record(seq, "GET", "/x", jsonReply(`{"v":"stable"}`), jsonReply(b), jsonReply(`{"v":"changed"}`)))
	}
	result := comparator.Result()
	wantKinds(t, result, "warning:value_changed_beyond_noise:$.v")
	if result.Noise[0].Decision != NoiseExceeded {
		t.Fatalf("noise = %+v", result.Noise)
	}
}

func TestCandidateWithinBaselineValuesIsNotADifference(t *testing.T) {
	comparator := newComparator(t, "", "")
	for seq := 1; seq <= 4; seq++ {
		comparator.Observe(record(seq, "GET", "/x", jsonReply(`{"v":"a"}`), jsonReply(`{"v":"b"}`), jsonReply(`{"v":"b"}`)))
	}
	result := comparator.Result()
	wantKinds(t, result, "info:noise_explained:$.v")
	if result.Noise[0].CandidateRate != 0 {
		t.Fatalf("noise = %+v", result.Noise)
	}
}

func TestNoiseOnOneRouteDoesNotExcuseAnother(t *testing.T) {
	comparator := newComparator(t, "", "")
	for seq := 1; seq <= 3; seq++ {
		comparator.Observe(noisy(seq, "/noisy", "", ""))
	}
	comparator.Observe(record(9, "GET", "/stable", jsonReply(`{"t":1}`), jsonReply(`{"t":1}`), jsonReply(`{"t":2}`)))
	wantKinds(t, comparator.Result(), "info:noise_explained:$.t", "warning:value_changed:$.t")
}

func TestBaselineStructuralDisagreementIsUncertain(t *testing.T) {
	wantKinds(t, compareOne(t, jsonReply(`{"a":1}`), jsonReply(`{}`), jsonReply(`{"a":1}`)),
		"uncertain:baseline_presence_unstable:$.a")
	wantKinds(t, compareOne(t, jsonReply(`{"a":1}`), jsonReply(`{"a":"x"}`), jsonReply(`{"a":1}`)),
		"uncertain:baseline_type_unstable:$.a")
}

func TestCandidateOutsideUnstableBaselineTypesIsStillBreaking(t *testing.T) {
	a, b := jsonReply(`{"a":1}`), jsonReply(`{"a":"x"}`)
	wantKinds(t, compareOne(t, a, b, jsonReply(`{}`)), "breaking:field_removed:$.a")
	wantKinds(t, compareOne(t, a, b, jsonReply(`{"a":true}`)), "breaking:type_changed:$.a")
}

func TestIgnoreRulesCoverValuesOnly(t *testing.T) {
	const config = `ignore: [{route: "GET /x", paths: ["$.t"]}]`
	comparator := newComparator(t, config, "")
	comparator.Observe(record(1, "GET", "/x", jsonReply(`{"t":1}`), jsonReply(`{"t":1}`), jsonReply(`{"t":2}`)))
	result := comparator.Result()
	wantKinds(t, result)
	if len(result.Ignored) != 1 || result.Ignored[0].Path != "$.t" || result.Ignored[0].Count != 1 || result.Ignored[0].Route != "GET /x" {
		t.Fatalf("ignored = %+v", result.Ignored)
	}

	comparator = newComparator(t, config, "")
	comparator.Observe(record(1, "GET", "/x", jsonReply(`{"t":1}`), jsonReply(`{"t":1}`), jsonReply(`{}`)))
	wantKinds(t, comparator.Result(), "breaking:field_removed:$.t")

	comparator = newComparator(t, config, "")
	comparator.Observe(record(1, "GET", "/x", jsonReply(`{"t":1}`), jsonReply(`{"t":1}`), jsonReply(`{"t":"1"}`)))
	wantKinds(t, comparator.Result(), "breaking:type_changed:$.t")
}

func TestIgnoreRuleScopes(t *testing.T) {
	base, candidate := jsonReply(`{"t":1,"s":"a","m":{"n":1}}`), jsonReply(`{"t":2,"s":"b","m":{"n":2}}`)
	for name, tc := range map[string]struct {
		config string
		want   []string
	}{
		"other route": {`ignore: [{route: "GET /other", paths: ["$.t","$.s","$.m"]}]`,
			[]string{"warning:value_changed:$.t", "warning:value_changed:$.s", "warning:value_changed:$.m.n"}},
		"other field": {`ignore: [{route: "GET /x", paths: ["$.s","$.m"]}]`,
			[]string{"warning:value_changed:$.t"}},
		"type scope": {`ignore: [{route: "GET /x", paths: ["$.t","$.s"], types: [string]}]`,
			[]string{"warning:value_changed:$.t", "warning:value_changed:$.m.n"}},
		"subtree":        {`ignore: [{route: "GET /x", paths: ["$.t","$.s","$.m"]}]`, nil},
		"wildcard route": {`ignore: [{route: "* /**", paths: ["$"]}]`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			comparator := newComparator(t, tc.config, "")
			comparator.Observe(record(1, "GET", "/x", base, base, candidate))
			wantKinds(t, comparator.Result(), tc.want...)
		})
	}
}

func TestIgnoreStructureMustBeExplicit(t *testing.T) {
	comparator := newComparator(t, `ignore: [{route: "GET /x", paths: ["$.debug"], ignore_structure: true}]`, "")
	comparator.Observe(record(1, "GET", "/x", jsonReply(`{"debug":{"a":1},"keep":1}`), jsonReply(`{"debug":{"a":1},"keep":1}`), jsonReply(`{"keep":1}`)))
	result := comparator.Result()
	wantKinds(t, result)
	if len(result.Ignored) != 1 || !result.Ignored[0].Structure {
		t.Fatalf("ignored = %+v", result.Ignored)
	}
}

func TestBodyChanges(t *testing.T) {
	js := jsonReply(`{"a":1}`)
	empty := reply{status: 200, contentType: jsonType}
	html := reply{status: 200, contentType: "text/html", body: "<p>page</p>"}
	bad := reply{status: 200, contentType: jsonType, body: `{"a":`}
	for name, tc := range map[string]struct {
		a, b, c reply
		want    []string
	}{
		"json to empty":     {js, js, empty, []string{"breaking:body_removed:"}},
		"json to malformed": {js, js, bad, []string{"breaking:body_invalid:"}},
		"json to html":      {js, js, html, []string{"breaking:body_type_changed:", "warning:content_type_changed:"}},
		"empty to json":     {empty, empty, js, []string{"info:body_added:"}},
		"all empty":         {empty, empty, empty, nil},
		"all html":          {html, html, html, []string{"uncertain:body_not_compared:"}},
		"baselines differ":  {js, html, js, []string{"uncertain:baseline_body_unstable:", "uncertain:baseline_content_type_unstable:"}},
		"all malformed":     {bad, bad, bad, []string{"uncertain:body_not_compared:"}},
	} {
		t.Run(name, func(t *testing.T) {
			wantKinds(t, compareOne(t, tc.a, tc.b, tc.c), tc.want...)
		})
	}
}

func TestContentTypeParametersAreIgnoredButTheTypeIsNot(t *testing.T) {
	base := reply{status: 200, contentType: "application/json; charset=utf-8", body: `{}`}
	wantKinds(t, compareOne(t, base, base, jsonReply(`{}`)))
	wantKinds(t, compareOne(t, base, base, reply{status: 200, contentType: "application/problem+json", body: `{}`}),
		"warning:content_type_changed:")
}

func TestOpaqueTextIsComparedAsAWhole(t *testing.T) {
	text := func(s string) reply { return reply{status: 200, contentType: "text/plain", body: s} }
	comparator := newComparator(t, "", `opaque_content_types: [text/plain]`)
	comparator.Observe(record(1, "GET", "/x", text("same"), text("same"), text("same")))
	comparator.Observe(record(2, "GET", "/x", text("old"), text("old"), text("new")))
	wantKinds(t, comparator.Result(), "warning:value_changed:$")
}

func TestConfiguredHeadersAreCompared(t *testing.T) {
	withHeader := func(v string) reply {
		r := jsonReply(`{}`)
		r.header = http.Header{"Cache-Control": {v}, "Date": {"varies " + v}}
		return r
	}
	comparator := newComparator(t, `compare_headers: [cache-control]`, "")
	comparator.Observe(record(1, "GET", "/x", withHeader("max-age=60"), withHeader("max-age=60"), withHeader("no-store")))
	wantKinds(t, comparator.Result(), "warning:value_changed:headers['Cache-Control']")

	comparator = newComparator(t, "", "")
	comparator.Observe(record(1, "GET", "/x", withHeader("max-age=60"), withHeader("max-age=60"), withHeader("no-store")))
	wantKinds(t, comparator.Result())
}

func TestSanitizedBeforeComparisonSoEvidenceCannotHoldCoveredValues(t *testing.T) {
	const secret = "rdsentinel-covered-value"
	comparator := newComparator(t, "", `json_paths: ["$.email"]`)
	comparator.Observe(record(1, "GET", "/x",
		jsonReply(`{"email":"`+secret+`-a","v":1}`),
		jsonReply(`{"email":"`+secret+`-b","v":1}`),
		jsonReply(`{"email":"`+secret+`-c","v":2}`)))
	result := comparator.Result()
	wantKinds(t, result, "warning:value_changed:$.v")
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("result holds a covered value: %s", data)
	}
}

func TestMalformedBodiesNeverReachEvidence(t *testing.T) {
	const secret = "rdsentinel-in-malformed-body"
	result := compareOne(t, jsonReply(`{"a":1}`), jsonReply(`{"a":1}`), reply{status: 200, contentType: jsonType, body: `{"a":"` + secret})
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("result holds an unparsed body: %s", data)
	}
}

func TestEvidenceShowsBoundedValuesAndDistinguishesMissingFromNull(t *testing.T) {
	comparator := newComparator(t, `limits: {max_evidence_bytes: 16}`, "")
	long := strings.Repeat("x", 200)
	comparator.Observe(record(7, "GET", "/x", jsonReply(`{"v":"`+long+`","n":null}`), jsonReply(`{"v":"`+long+`","n":null}`), jsonReply(`{"v":"y"}`)))
	result := comparator.Result()
	var value, removed *Finding
	for i := range result.Findings {
		switch result.Findings[i].Kind {
		case KindValueChanged:
			value = &result.Findings[i]
		case KindFieldRemoved:
			removed = &result.Findings[i]
		}
	}
	if value == nil || removed == nil {
		t.Fatalf("findings = %+v", result.Findings)
	}
	if value.Evidence.RecordID != "rec-0007" || !value.Evidence.BaselineA.Present || len(value.Evidence.BaselineA.Text) > 20 {
		t.Fatalf("evidence = %+v", value.Evidence)
	}
	if removed.Evidence.Candidate.Present || !removed.Evidence.BaselineA.Present || removed.Evidence.BaselineA.Type != "null" {
		t.Fatalf("evidence = %+v", removed.Evidence)
	}
}

func TestEvidenceTypesModeOmitsValues(t *testing.T) {
	comparator := newComparator(t, `evidence: types`, "")
	comparator.Observe(record(1, "GET", "/x", jsonReply(`{"v":"private"}`), jsonReply(`{"v":"private"}`), jsonReply(`{"v":"other"}`)))
	result := comparator.Result()
	data, err := json.Marshal(result.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private") {
		t.Fatalf("findings = %s", data)
	}
	if result.Findings[0].Evidence.Candidate.Type != "string" {
		t.Fatalf("evidence = %+v", result.Findings[0].Evidence)
	}
}

func TestRepeatedFindingsAreAggregatedWithCounts(t *testing.T) {
	comparator := newComparator(t, "", "")
	for seq := 5; seq >= 1; seq-- {
		comparator.Observe(record(seq, "GET", fmt.Sprintf("/orders/o%d", seq), jsonReply(`{"a":1}`), jsonReply(`{"a":1}`), jsonReply(`{}`)))
	}
	result := comparator.Result()
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	finding := result.Findings[0]
	if finding.Route != "GET /orders/*" || finding.Count != 5 {
		t.Fatalf("finding = %+v", finding)
	}
	if finding.Evidence.Seq != 1 {
		t.Fatalf("evidence must come from the lowest sequence, got %d", finding.Evidence.Seq)
	}
}

func TestSeverityCountsAndOrdering(t *testing.T) {
	comparator := newComparator(t, "", "")
	comparator.Observe(record(1, "GET", "/z", jsonReply(`{"a":1}`), jsonReply(`{"a":1}`), jsonReply(`{"b":1}`)))
	comparator.Observe(record(2, "GET", "/a", jsonReply(`{"v":1}`), jsonReply(`{"v":1}`), jsonReply(`{"v":2}`)))
	comparator.Observe(record(3, "GET", "/m", jsonReply(`{"q":1}`), jsonReply(`{"q":2}`), jsonReply(`{"q":3}`)))
	result := comparator.Result()
	var severities []Severity
	for _, f := range result.Findings {
		severities = append(severities, f.Severity)
	}
	want := []Severity{SeverityBreaking, SeverityWarning, SeverityUncertain, SeverityInfo}
	if !slices.Equal(severities, want) {
		t.Fatalf("severities = %v", severities)
	}
	if result.Counts[SeverityBreaking] != 1 || result.Counts[SeverityWarning] != 1 || result.Counts[SeverityUncertain] != 1 || result.Counts[SeverityInfo] != 1 {
		t.Fatalf("counts = %+v", result.Counts)
	}
}

func TestResultDoesNotDependOnArrivalOrder(t *testing.T) {
	var records []*replay.RecordResult
	for seq := 1; seq <= 40; seq++ {
		records = append(records, record(seq, "GET", fmt.Sprintf("/r%d/x", seq%3),
			jsonReply(fmt.Sprintf(`{"t":%d,"s":1,"a":[1,2]}`, seq)),
			jsonReply(fmt.Sprintf(`{"t":%d,"s":1,"a":[1,2]}`, seq+100)),
			jsonReply(fmt.Sprintf(`{"t":%d,"s":2}`, seq+200))))
	}
	encode := func(order []*replay.RecordResult) string {
		comparator := newComparator(t, "", "")
		for _, r := range order {
			comparator.Observe(r)
		}
		data, err := json.Marshal(comparator.Result())
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	first := encode(records)
	shuffled := slices.Clone(records)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	if second := encode(shuffled); first != second {
		t.Fatalf("results differ by arrival order:\n%s\n%s", first, second)
	}
}

func TestLimitsBoundFieldsFindingsAndRoutes(t *testing.T) {
	comparator := newComparator(t, `limits: {max_fields_per_route: 5, max_findings: 3, max_routes: 2}`, "")
	var base, candidate strings.Builder
	base.WriteString("{")
	candidate.WriteString("{")
	for i := range 50 {
		if i > 0 {
			base.WriteString(",")
			candidate.WriteString(",")
		}
		fmt.Fprintf(&base, `"f%d":1`, i)
		fmt.Fprintf(&candidate, `"f%d":2`, i)
	}
	base.WriteString("}")
	candidate.WriteString("}")
	a, c := jsonReply(base.String()), jsonReply(candidate.String())
	for i := range 4 {
		comparator.Observe(record(i+1, "GET", fmt.Sprintf("/r%c", 'a'+byte(i)), a, a, c))
	}
	result := comparator.Result()
	if len(result.Findings) != 3 {
		t.Fatalf("findings = %d", len(result.Findings))
	}
	if result.Truncated.Findings == 0 || result.Truncated.Fields == 0 || result.Truncated.RouteRecords != 2 {
		t.Fatalf("truncated = %+v", result.Truncated)
	}
	// Counts cover everything, including what the list had to leave out.
	if result.Counts[SeverityWarning] < 5 {
		t.Fatalf("counts = %+v", result.Counts)
	}
	seenLimit := false
	for _, kind := range result.Limited {
		if kind.Kind == KindFieldLimitReached && kind.Severity == SeverityUncertain {
			seenLimit = true
		}
	}
	if !seenLimit {
		t.Fatalf("a reached limit must be reported as uncertain: %+v", result.Limited)
	}
}

func TestDeepNestingIsBounded(t *testing.T) {
	deep := func(leaf string) reply {
		const depth = 5000
		return jsonReply(strings.Repeat(`{"a":`, depth) + leaf + strings.Repeat("}", depth))
	}
	result := compareOne(t, deep("1"), deep("1"), deep("2"))
	if len(result.Findings) != 1 || result.Findings[0].Kind != KindValueChanged {
		t.Fatalf("findings = %+v", kinds(result))
	}
	if len(result.Findings[0].Path) > 2000 {
		t.Fatalf("path length = %d", len(result.Findings[0].Path))
	}
}

func TestConcurrentObserveIsSafe(t *testing.T) {
	comparator := newComparator(t, "", "")
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 50 {
				comparator.Observe(record(worker*100+i+1, "GET", "/x", jsonReply(`{"a":1}`), jsonReply(`{"a":1}`), jsonReply(`{}`)))
			}
		})
	}
	wg.Wait()
	result := comparator.Result()
	if result.Findings[0].Count != 400 || result.Coverage.Compared != 400 {
		t.Fatalf("result = %+v", result)
	}
}

func TestPercentileUsesNearestRank(t *testing.T) {
	sorted := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, tc := range []struct {
		p    float64
		want int64
	}{{1, 10}, {10, 10}, {11, 20}, {50, 50}, {51, 60}, {90, 90}, {95, 100}, {99, 100}, {100, 100}} {
		if got := percentile(sorted, tc.p); got != tc.want {
			t.Errorf("percentile(%v) = %d, want %d", tc.p, got, tc.want)
		}
	}
	if got := percentile([]int64{7}, 50); got != 7 {
		t.Errorf("single sample = %d", got)
	}
	if got := percentile(nil, 50); got != 0 {
		t.Errorf("no samples = %d", got)
	}
}

func observeLatency(comparator *Comparator, n int, a, b, c func(i int) int64) {
	for i := range n {
		ra, rb, rc := jsonReply(`{}`), jsonReply(`{}`), jsonReply(`{}`)
		ra.latency, rb.latency, rc.latency = a(i), b(i), c(i)
		comparator.Observe(record(i+1, "GET", "/slow", ra, rb, rc))
	}
}

func constant(v int64) func(int) int64 { return func(int) int64 { return v } }

func TestLatencyRegressionNeedsSamplesPercentAndAbsoluteIncrease(t *testing.T) {
	for name, tc := range map[string]struct {
		samples   int
		base, cnd int64
		want      []string
		evaluated bool
	}{
		"regression":          {20, 10_000, 30_000, []string{"warning:latency_regression:p50", "warning:latency_regression:p95", "warning:latency_regression:p99"}, true},
		"too few samples":     {19, 10_000, 30_000, nil, false},
		"within percent":      {20, 100_000, 110_000, nil, true},
		"below absolute":      {20, 100, 3_000, nil, true},
		"candidate is faster": {20, 30_000, 10_000, nil, true},
	} {
		t.Run(name, func(t *testing.T) {
			comparator := newComparator(t, "", "")
			observeLatency(comparator, tc.samples, constant(tc.base), constant(tc.base), constant(tc.cnd))
			result := comparator.Result()
			wantKinds(t, result, tc.want...)
			if len(result.Routes) != 1 || result.Routes[0].Latency.Evaluated != tc.evaluated {
				t.Fatalf("routes = %+v", result.Routes)
			}
		})
	}
}

func TestLatencyIsComparedWithTheSlowerBaseline(t *testing.T) {
	comparator := newComparator(t, "", "")
	observeLatency(comparator, 20, constant(10_000), constant(30_000), constant(31_000))
	wantKinds(t, comparator.Result())
}

func TestLatencyUsesTheSamePercentileAcrossTargets(t *testing.T) {
	comparator := newComparator(t, `latency: {percentiles: [99], min_samples: 10}`, "")
	// One slow outlier on the candidate shows at p99 but not at the median.
	tail := func(i int) int64 {
		if i == 99 {
			return 90_000
		}
		return 1_000
	}
	observeLatency(comparator, 100, constant(1_000), constant(1_000), tail)
	result := comparator.Result()
	row := result.Routes[0].Latency.Percentiles[0]
	if row.Percentile != 99 || row.CandidateMicros != 1_000 {
		t.Fatalf("p99 of 100 samples is the 99th value, got %+v", row)
	}
	wantKinds(t, result)
}

func TestLatencySkipsRecordsThatFailedOnAnyTarget(t *testing.T) {
	comparator := newComparator(t, `latency: {min_samples: 1}`, "")
	bad := reply{outcome: replay.CallTimeout, latency: 999_000}
	ok := jsonReply(`{}`)
	ok.latency = 1_000
	comparator.Observe(record(1, "GET", "/x", ok, ok, bad))
	result := comparator.Result()
	if result.Routes[0].Latency.Samples != 0 {
		t.Fatalf("latency = %+v", result.Routes[0].Latency)
	}
}

func TestLatencySamplesAreBoundedPerRoute(t *testing.T) {
	comparator := newComparator(t, "", "")
	observeLatency(comparator, maxLatencySamples+500, constant(1_000), constant(1_000), constant(1_000))
	result := comparator.Result()
	if result.Routes[0].Latency.Samples != maxLatencySamples+500 {
		t.Fatalf("samples = %d", result.Routes[0].Latency.Samples)
	}
	for _, route := range comparator.routes {
		for _, samples := range route.latency {
			if len(samples) > maxLatencySamples {
				t.Fatalf("held %d samples", len(samples))
			}
		}
	}
}

func TestErrorRateRegression(t *testing.T) {
	run := func(config string, n, candidateErrors int) *Result {
		comparator := newComparator(t, config, "")
		for i := range n {
			c := jsonReply(`{}`)
			if i < candidateErrors {
				c.status = 500
			}
			comparator.Observe(record(i+1, "GET", "/x", jsonReply(`{}`), jsonReply(`{}`), c))
		}
		return comparator.Result()
	}
	has := func(result *Result) bool {
		for _, f := range result.Findings {
			if f.Kind == KindErrorRateRegression {
				return true
			}
		}
		return false
	}
	if !has(run("", 100, 2)) {
		t.Fatal("2 points over a 1 point limit must be reported")
	}
	if has(run("", 100, 1)) {
		t.Fatal("exactly the limit must not be reported")
	}
	if has(run("", 19, 19)) {
		t.Fatal("below the minimum requests must not be reported")
	}
	if !has(run(`error_rate: {min_requests: 5}`, 5, 5)) {
		t.Fatal("the minimum must be configurable")
	}
}

func TestNewRequiresAnEngine(t *testing.T) {
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("responses can't be compared without being sanitized")
	}
}

// math/big has its own limit near an exponent of a million, but numbers just under it
// are very expensive to expand, so a response could use them to burn CPU.
func TestExactNumberComparisonIsBounded(t *testing.T) {
	for text, want := range map[string]bool{
		"1":                      true,
		"1.5e10":                 true,
		"1e1000":                 true,
		"1e-1000":                true,
		"1e1001":                 false,
		"1E-1001":                false,
		"1e900000":               false,
		"1e99999999999999999999": false,
		strings.Repeat("1", 512): true,
		strings.Repeat("1", 513): false,
	} {
		if _, got := exactNumber(text); got != want {
			t.Errorf("exactNumber(%.30q) = %t, want %t", text, got, want)
		}
	}
}

// observeRates feeds n comparisons where the baselines disagree on the first
// disagreements of them, and the candidate differs from both on the first differences.
func observeRates(comparator *Comparator, n, disagreements, differences int) {
	for i := range n {
		a, b := `{"v":"same"}`, `{"v":"same"}`
		if i < disagreements {
			b = `{"v":"other"}`
		}
		c := a
		if i < differences {
			c = `{"v":"changed"}`
		}
		comparator.Observe(record(i+1, "GET", "/x", jsonReply(a), jsonReply(b), jsonReply(c)))
	}
}

// A gap between rates means little on few observations. Two timestamps colliding by
// chance mustn't produce a warning, and it mustn't produce false confidence either.
func TestNoiseDecisionAccountsForSampleSize(t *testing.T) {
	for name, tc := range map[string]struct {
		n, disagreements, differences int
		want                          string
		finding                       string
	}{
		"small gap is noise":             {5, 4, 5, NoiseExplained, "info:noise_explained:$.v"},
		"equal rates are noise":          {3, 3, 3, NoiseExplained, "info:noise_explained:$.v"},
		"large gap on few is uncertain":  {5, 3, 5, NoiseInsufficient, "uncertain:insufficient_baseline_evidence:$.v"},
		"very rare noise on few":         {3, 1, 3, NoiseInsufficient, "uncertain:insufficient_baseline_evidence:$.v"},
		"clear gap on some is exceeded":  {10, 1, 10, NoiseExceeded, "warning:value_changed_beyond_noise:$.v"},
		"same gap on many is exceeded":   {200, 120, 200, NoiseExceeded, "warning:value_changed_beyond_noise:$.v"},
		"small gap on many is noise":     {1000, 900, 1000, NoiseExplained, "info:noise_explained:$.v"},
		"candidate rate below baselines": {50, 40, 5, NoiseExplained, "info:noise_explained:$.v"},
	} {
		t.Run(name, func(t *testing.T) {
			comparator := newComparator(t, "", "")
			observeRates(comparator, tc.n, tc.disagreements, tc.differences)
			result := comparator.Result()
			wantKinds(t, result, tc.finding)
			if result.Noise[0].Decision != tc.want {
				t.Fatalf("decision = %+v", result.Noise[0])
			}
		})
	}
}

func TestWilsonIntervalIsBoundedAndContainsTheRate(t *testing.T) {
	for _, tc := range []struct{ successes, n int }{{0, 1}, {1, 1}, {0, 100}, {100, 100}, {1, 10}, {3, 5}, {500, 1000}} {
		low, high := wilsonInterval(tc.successes, tc.n)
		rate := float64(tc.successes) / float64(tc.n)
		if low < 0 || high > 1 || low > rate || high < rate {
			t.Errorf("wilsonInterval(%d, %d) = %v, %v for rate %v", tc.successes, tc.n, low, high, rate)
		}
	}
	narrowLow, narrowHigh := wilsonInterval(500, 1000)
	wideLow, wideHigh := wilsonInterval(5, 10)
	if narrowHigh-narrowLow >= wideHigh-wideLow {
		t.Fatal("more observations must narrow the interval")
	}
}

// Noise applies to a field on a route and of a type. Disagreement about strings says
// nothing about whether a change to the same field's numbers is real.
func TestNoiseIsTrackedSeparatelyByType(t *testing.T) {
	comparator := newComparator(t, "", "")
	seq := 0
	observe := func(a, b, c string) {
		seq++
		comparator.Observe(record(seq, "GET", "/x", jsonReply(a), jsonReply(b), jsonReply(c)))
	}
	for i := range 10 {
		if i < 4 {
			observe(`{"v":"same"}`, `{"v":"other"}`, `{"v":"same"}`)
		} else {
			observe(`{"v":"same"}`, `{"v":"same"}`, `{"v":"same"}`)
		}
	}
	for i := range 10 {
		if i < 6 {
			observe(`{"v":1}`, `{"v":1}`, `{"v":2}`)
		} else {
			observe(`{"v":1}`, `{"v":1}`, `{"v":1}`)
		}
	}
	result := comparator.Result()
	wantKinds(t, result, "info:noise_explained:$.v", "warning:value_changed:$.v")
	for _, finding := range result.Findings {
		want := "string"
		if finding.Kind == KindValueChanged {
			want = "number"
		}
		if finding.ValueType != want {
			t.Errorf("%s has value type %q, want %q", finding.Kind, finding.ValueType, want)
		}
	}
	if len(result.Noise) != 1 || result.Noise[0].Type != "string" {
		t.Fatalf("noise = %+v", result.Noise)
	}
}

// A type listed as opaque is compared whole, even if its name ends in "json". Parsing it
// as JSON would read only the first value of newline-delimited data.
func TestOpaqueTypesNamedLikeJSONAreComparedWhole(t *testing.T) {
	const media = "application/x-ndjson"
	reply := func(body string) reply { return reply{status: 200, contentType: media, body: body} }
	comparator := newComparator(t, "", `opaque_content_types: [application/x-ndjson]`)
	comparator.Observe(record(1, "GET", "/x", reply("{\"a\":1}\n{\"a\":2}\n"), reply("{\"a\":1}\n{\"a\":2}\n"), reply("{\"a\":1}\n{\"a\":3}\n")))
	wantKinds(t, comparator.Result(), "warning:value_changed:$")
}

func TestHeadersThatAreNeverStoredCannotBeCompared(t *testing.T) {
	for _, name := range []string{"ETag", "etag", "Content-Length", "Content-Encoding", "Digest", "Connection", "Transfer-Encoding", "Trailer"} {
		if _, err := ParseConfig([]byte(`compare_headers: ["` + name + `"]`)); err == nil {
			t.Errorf("compare_headers %s must be refused: it would never be compared, and nothing would say so", name)
		}
	}
	if _, err := ParseConfig([]byte(`compare_headers: [Cache-Control, Vary]`)); err != nil {
		t.Fatal(err)
	}
}
