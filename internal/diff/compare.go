package diff

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand/v2"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Bispulm/replaydiff/internal/redact"
	"github.com/Bispulm/replaydiff/internal/replay"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

const (
	// maxLatencySamples bounds samples held per route and target. Beyond it, samples
	// are replaced at random so that the held ones stay a uniform sample.
	maxLatencySamples = 4096
	// maxDepth bounds recursion, and with it the length of a path. Anything deeper is
	// compared as a single value.
	maxDepth = 64
	// maxKeyBytes bounds one object key in a path.
	maxKeyBytes = 64
	// maxExactExponent bounds exact numeric comparison, whose cost grows with the
	// exponent. Numbers beyond it are compared by their text.
	maxExactExponent = 1000
	maxExactDigits   = 512
)

// fieldStats accumulates comparisons of one field on one route.
type fieldStats struct {
	typeName         string
	isLength         bool
	observations     int
	baselineDisagree int
	candidateStable  int
	candidateNoisy   int
	counts           map[Kind]int
	evidence         map[Kind]*Evidence
	ignoredValues    int
	ignoredStructure int
}

func (f *fieldStats) note(kind Kind, evidence *Evidence) {
	if f.counts == nil {
		f.counts = make(map[Kind]int)
	}
	f.counts[kind]++
	f.keepEvidence(kind, evidence)
}

func (f *fieldStats) keepEvidence(kind Kind, evidence *Evidence) {
	if evidence == nil {
		return
	}
	if f.evidence == nil {
		f.evidence = make(map[Kind]*Evidence)
	}
	if current := f.evidence[kind]; current == nil || evidence.Seq < current.Seq {
		f.evidence[kind] = evidence
	}
}

func (f *fieldStats) merge(other *fieldStats) {
	f.typeName = cmp.Or(f.typeName, other.typeName)
	f.isLength = f.isLength || other.isLength
	f.observations += other.observations
	f.baselineDisagree += other.baselineDisagree
	f.candidateStable += other.candidateStable
	f.candidateNoisy += other.candidateNoisy
	f.ignoredValues += other.ignoredValues
	f.ignoredStructure += other.ignoredStructure
	for kind, n := range other.counts {
		if f.counts == nil {
			f.counts = make(map[Kind]int)
		}
		f.counts[kind] += n
	}
	for kind, evidence := range other.evidence {
		f.keepEvidence(kind, evidence)
	}
}

type routeState struct {
	records         int
	fields          map[string]*fieldStats
	fieldsDropped   int
	latency         [3][]int64
	latencySamples  int
	baselineErrors  int
	candidateErrors int
}

// compiledRule is an ignore or unordered rule with its route pattern parsed.
type compiledRule struct {
	pattern *routePattern
	paths   []string
	types   []string
	both    bool
}

func (r *compiledRule) coversField(path string) bool {
	return slices.ContainsFunc(r.paths, func(rule string) bool { return pathMatchesRule(rule, path) })
}

// Comparator compares results as they arrive and keeps counts rather than bodies, so
// its memory doesn't grow with traffic. It is safe for concurrent use.
type Comparator struct {
	cfg        *Config
	engine     *redact.Engine
	classifier *routeClassifier
	ignore     []compiledRule
	unordered  []compiledRule
	headers    []string

	mu          sync.Mutex
	routes      map[string]*routeState
	records     int
	compared    int
	notCompared map[string]int
}

// New returns a Comparator. Responses are sanitized with engine before anything else
// happens to them, so that evidence can't hold values the policy covers.
func New(cfg *Config, engine *redact.Engine) (*Comparator, error) {
	if engine == nil {
		return nil, errors.New("diff: a redaction engine is required")
	}
	classifier, err := newRouteClassifier(cfg.Routes, cfg.Limits.MaxRoutes)
	if err != nil {
		return nil, err
	}
	c := &Comparator{
		cfg:         cfg,
		engine:      engine,
		classifier:  classifier,
		routes:      make(map[string]*routeState),
		notCompared: make(map[string]int),
	}
	for _, rule := range cfg.Ignore {
		pattern, err := parseRoutePattern(rule.Route)
		if err != nil {
			return nil, err
		}
		c.ignore = append(c.ignore, compiledRule{pattern: pattern, paths: rule.Paths, types: rule.Types, both: rule.IgnoreStructure})
	}
	for _, rule := range cfg.UnorderedArrays {
		pattern, err := parseRoutePattern(rule.Route)
		if err != nil {
			return nil, err
		}
		c.unordered = append(c.unordered, compiledRule{pattern: pattern, paths: rule.Paths})
	}
	for _, name := range cfg.CompareHeaders {
		c.headers = append(c.headers, http.CanonicalHeaderKey(name))
	}
	return c, nil
}

// recordCompare holds what one record contributed, built without holding a lock.
type recordCompare struct {
	c         *Comparator
	result    *replay.RecordResult
	fields    map[string]*fieldStats
	ignore    []compiledRule
	unordered []compiledRule
}

func (r *recordCompare) field(path string) *fieldStats {
	f := r.fields[path]
	if f == nil {
		f = &fieldStats{}
		r.fields[path] = f
	}
	return f
}

// Observe compares one record's results. It may be called concurrently.
func (c *Comparator) Observe(result *replay.RecordResult) {
	a, b, candidate := &result.Calls[replay.RoleBaselineA], &result.Calls[replay.RoleBaselineB], &result.Calls[replay.RoleCandidate]
	route := c.classifier.route(result.Method, result.Path)
	rc := &recordCompare{c: c, result: result, fields: make(map[string]*fieldStats)}
	for i := range c.ignore {
		if c.ignore[i].pattern.matches(result.Method, result.Path) {
			rc.ignore = append(rc.ignore, c.ignore[i])
		}
	}
	for i := range c.unordered {
		if c.unordered[i].pattern.matches(result.Method, result.Path) {
			rc.unordered = append(rc.unordered, c.unordered[i])
		}
	}

	baselinesOK := a.Outcome == replay.CallOK && b.Outcome == replay.CallOK
	if baselinesOK {
		rc.compareCalls(a, b, candidate)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.records++
	if baselinesOK {
		c.compared++
	} else {
		c.notCompared["baseline_failed"]++
	}
	state := c.routes[route]
	if state == nil {
		state = &routeState{fields: make(map[string]*fieldStats)}
		c.routes[route] = state
	}
	state.records++
	for path, stats := range rc.fields {
		existing := state.fields[path]
		if existing == nil {
			if len(state.fields) >= c.cfg.Limits.MaxFieldsPerRoute {
				state.fieldsDropped++
				continue
			}
			state.fields[path] = stats
			continue
		}
		existing.merge(stats)
	}
	if isErrorCall(a) {
		state.baselineErrors++
	}
	if isErrorCall(b) {
		state.baselineErrors++
	}
	if isErrorCall(candidate) {
		state.candidateErrors++
	}
	if baselinesOK && candidate.Outcome == replay.CallOK {
		state.latencySamples++
		for i, call := range []*replay.CallResult{a, b, candidate} {
			if len(state.latency[i]) < maxLatencySamples {
				state.latency[i] = append(state.latency[i], call.LatencyMicros)
			} else if j := rand.IntN(state.latencySamples); j < maxLatencySamples {
				state.latency[i][j] = call.LatencyMicros
			}
		}
	}
}

func isErrorCall(call *replay.CallResult) bool {
	return call.Outcome != replay.CallOK || call.Status >= 500
}

func (r *recordCompare) evidence(field string, a, b, c Value) *Evidence {
	return &Evidence{RecordID: r.result.ID, Seq: r.result.Seq, Field: field, BaselineA: a, BaselineB: b, Candidate: c}
}

func statusValue(status int) Value {
	return Value{Present: true, Type: "status", Text: strconv.Itoa(status)}
}

func (r *recordCompare) compareCalls(a, b, candidate *replay.CallResult) {
	overall := r.field("")
	if candidate.Outcome != replay.CallOK {
		overall.note(KindCandidateCallFailed, r.evidence("", statusValue(a.Status), statusValue(b.Status), Value{Present: true, Type: "outcome", Text: string(candidate.Outcome)}))
		return
	}

	statusEvidence := func() *Evidence {
		return r.evidence("", statusValue(a.Status), statusValue(b.Status), statusValue(candidate.Status))
	}
	if a.Status != b.Status {
		// Different statuses mean different kinds of response, so their bodies aren't
		// comparable either. A class neither baseline produced is still a real change.
		overall.note(KindBaselineStatusUnstable, statusEvidence())
		if candidate.Status/100 != a.Status/100 && candidate.Status/100 != b.Status/100 {
			overall.note(KindStatusClassChanged, statusEvidence())
		}
		return
	}
	if candidate.Status/100 != a.Status/100 {
		overall.note(KindStatusClassChanged, statusEvidence())
		return
	}
	if candidate.Status != a.Status {
		overall.note(KindStatusChanged, statusEvidence())
	}

	r.compareContentType(a, b, candidate)
	r.compareHeaders(a, b, candidate)
	r.compareBodies(a, b, candidate)
}

func mediaType(call *replay.CallResult) string {
	value := call.Header.Get("Content-Type")
	if parsed, _, err := mime.ParseMediaType(value); err == nil {
		return parsed
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func (r *recordCompare) compareContentType(a, b, candidate *replay.CallResult) {
	ma, mb, mc := mediaType(a), mediaType(b), mediaType(candidate)
	value := func(m string) Value { return r.c.boundedValue("content-type", m) }
	switch {
	case ma != mb:
		r.field("").note(KindBaselineContentTypeUnstable, r.evidence("", value(ma), value(mb), value(mc)))
	case mc != ma:
		r.field("").note(KindContentTypeChanged, r.evidence("", value(ma), value(mb), value(mc)))
	}
}

func (r *recordCompare) compareHeaders(a, b, candidate *replay.CallResult) {
	var discard redact.Hits
	for _, name := range r.c.headers {
		get := func(call *replay.CallResult) (any, bool) {
			sanitized := r.c.engine.Headers(redact.ResponseHeader, http.Header{name: call.Header.Values(name)}, &discard)
			values, ok := sanitized[name]
			if !ok || len(values) == 0 {
				return nil, false
			}
			return strings.Join(values, ","), true
		}
		va, pa := get(a)
		vb, pb := get(b)
		vc, pc := get(candidate)
		path := "headers['" + name + "']"
		r.compareNode(path, path, 0, va, vb, vc, pa, pb, pc)
	}
}

// bodyView is a sanitized response body, ready to compare.
type bodyView struct {
	kind   bodyKind
	tree   any
	failed bool
}

type bodyKind int

const (
	viewEmpty bodyKind = iota
	viewJSON
	viewText
	viewOmitted
)

// textBody marks a whole non-JSON body being compared as one value.
type textBody string

func (r *recordCompare) view(call *replay.CallResult) bodyView {
	var discard redact.Hits
	sanitized := r.c.engine.Body(redact.ResponseBody, redact.BodyInput{
		ContentType:     call.Header.Get("Content-Type"),
		ContentEncoding: strings.Join(call.Header.Values("Content-Encoding"), ","),
		Data:            call.Body,
	}, &discard)
	switch sanitized.Body.State {
	case traffic.BodyEmpty:
		return bodyView{kind: viewEmpty}
	case traffic.BodyPresent:
		if !strings.HasSuffix(sanitized.Body.ContentType, "json") {
			return bodyView{kind: viewText, tree: textBody(sanitized.Body.Data)}
		}
		dec := json.NewDecoder(bytes.NewReader(sanitized.Body.Data))
		dec.UseNumber()
		var tree any
		if err := dec.Decode(&tree); err != nil {
			return bodyView{kind: viewOmitted, failed: true}
		}
		return bodyView{kind: viewJSON, tree: tree}
	default:
		return bodyView{kind: viewOmitted, failed: sanitized.Failed}
	}
}

func (r *recordCompare) compareBodies(a, b, candidate *replay.CallResult) {
	va, vb, vc := r.view(a), r.view(b), r.view(candidate)
	overall := r.field("")
	note := func(kind Kind) {
		overall.note(kind, r.evidence("", Value{Present: true}, Value{Present: true}, Value{Present: true}))
	}
	if va.kind != vb.kind {
		note(KindBaselineBodyUnstable)
		return
	}
	switch va.kind {
	case viewOmitted:
		note(KindBodyNotCompared)
	case viewEmpty:
		if vc.kind != viewEmpty {
			note(KindBodyAdded)
		}
	case viewJSON, viewText:
		switch {
		case vc.kind == viewEmpty:
			note(KindBodyRemoved)
		case vc.kind == viewOmitted && vc.failed:
			note(KindBodyInvalid)
		case vc.kind != va.kind:
			note(KindBodyTypeChanged)
		default:
			r.compareNode("$", "$", 0, va.tree, vb.tree, vc.tree, true, true, true)
		}
	}
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "boolean"
	case textBody:
		return "text"
	default:
		return "unknown"
	}
}

func (c *Comparator) boundedValue(typ string, text string) Value {
	return c.value(typ, text, true)
}

func (c *Comparator) value(typ, text string, present bool) Value {
	if !present {
		return Value{}
	}
	out := Value{Present: true, Type: typ}
	if c.cfg.Evidence != EvidenceValues || c.cfg.Limits.MaxEvidenceBytes == 0 {
		return out
	}
	limit := c.cfg.Limits.MaxEvidenceBytes
	if len(text) > limit {
		for limit > 0 && text[limit]&0xC0 == 0x80 {
			limit--
		}
		text = text[:limit] + "..."
	}
	out.Text = text
	return out
}

func (r *recordCompare) evidenceValue(v any, present bool) Value {
	if !present {
		return Value{}
	}
	typ := typeName(v)
	if text, ok := v.(textBody); ok {
		return r.c.value(typ, string(text), true)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return Value{Present: true, Type: typ}
	}
	return r.c.value(typ, string(data), true)
}

func (r *recordCompare) nodeEvidence(concrete string, a, b, c any, pa, pb, pc bool) *Evidence {
	return r.evidence(concrete, r.evidenceValue(a, pa), r.evidenceValue(b, pb), r.evidenceValue(c, pc))
}

func (r *recordCompare) ignoredStructure(path string) bool {
	return slices.ContainsFunc(r.ignore, func(rule compiledRule) bool { return rule.both && rule.coversField(path) })
}

func (r *recordCompare) ignoredValue(path, typ string) bool {
	return slices.ContainsFunc(r.ignore, func(rule compiledRule) bool {
		return rule.coversField(path) && (len(rule.types) == 0 || slices.Contains(rule.types, typ))
	})
}

// compareNode compares one position in three trees. Structure is checked first and
// doesn't depend on values, which is what keeps a removed or retyped field detectable
// however much its value varies.
func (r *recordCompare) compareNode(path, concrete string, depth int, a, b, c any, pa, pb, pc bool) {
	if r.ignoredStructure(path) {
		if differs(a, b, c, pa, pb, pc) {
			r.field(path).ignoredStructure++
		}
		return
	}
	evidence := func() *Evidence { return r.nodeEvidence(concrete, a, b, c, pa, pb, pc) }
	switch {
	case !pa && !pb:
		if pc {
			r.field(path).note(KindFieldAdded, evidence())
		}
		return
	case pa != pb:
		// One baseline has it and the other doesn't, so its presence can't be judged.
		r.field(path).note(KindBaselinePresenceUnstable, evidence())
		return
	case !pc:
		r.field(path).note(KindFieldRemoved, evidence())
		return
	}

	ta, tb, tc := typeName(a), typeName(b), typeName(c)
	if ta != tb {
		if tc != ta && tc != tb {
			r.field(path).note(KindTypeChanged, evidence())
			return
		}
		r.field(path).note(KindBaselineTypeUnstable, evidence())
		return
	}
	if tc != ta {
		r.field(path).note(KindTypeChanged, evidence())
		return
	}

	if depth < maxDepth {
		switch ta {
		case "object":
			r.compareObjects(path, concrete, depth, a.(map[string]any), b.(map[string]any), c.(map[string]any))
			return
		case "array":
			r.compareArrays(path, concrete, depth, a.([]any), b.([]any), c.([]any))
			return
		}
	}
	r.compareLeaf(path, concrete, ta, a, b, c)
}

func differs(a, b, c any, pa, pb, pc bool) bool {
	if pa != pb || pb != pc {
		return true
	}
	return canonical(a) != canonical(b) || canonical(b) != canonical(c)
}

func (r *recordCompare) compareObjects(path, concrete string, depth int, a, b, c map[string]any) {
	keys := make([]string, 0, len(a))
	for key := range a {
		keys = append(keys, key)
	}
	for _, other := range []map[string]any{b, c} {
		for key := range other {
			if _, seen := a[key]; !seen {
				keys = append(keys, key)
			}
		}
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	for _, key := range keys {
		va, pa := a[key]
		vb, pb := b[key]
		vc, pc := c[key]
		segment := pathSegment(key)
		r.compareNode(path+segment, concrete+segment, depth+1, va, vb, vc, pa, pb, pc)
	}
}

func (r *recordCompare) compareArrays(path, concrete string, depth int, a, b, c []any) {
	if slices.ContainsFunc(r.unordered, func(rule compiledRule) bool { return slices.Contains(rule.paths, path) }) {
		a, b, c = sortedByValue(a), sortedByValue(b), sortedByValue(c)
	}
	la, lb, lc := len(a), len(b), len(c)
	lengthKey := path + "#length"
	lengths := r.field(lengthKey)
	lengths.isLength = true
	lengths.typeName = "array_length"
	lengthEvidence := func() *Evidence {
		value := func(n int) Value { return r.c.value("number", strconv.Itoa(n), true) }
		return r.evidence(concrete, value(la), value(lb), value(lc))
	}
	if r.ignoredValue(path, "array") {
		if la != lb || la != lc {
			lengths.ignoredValues++
		}
	} else {
		r.tally(lengths, la == lb, la == lc, lb == lc, lengthEvidence)
	}

	limit := min(la, lb, lc)
	elementPath := path + "[*]"
	for i := range limit {
		r.compareNode(elementPath, concrete+"["+strconv.Itoa(i)+"]", depth+1, a[i], b[i], c[i], true, true, true)
	}
}

func sortedByValue(values []any) []any {
	type keyed struct {
		key   string
		value any
	}
	items := make([]keyed, len(values))
	for i, value := range values {
		items[i] = keyed{canonical(value), value}
	}
	slices.SortStableFunc(items, func(x, y keyed) int { return strings.Compare(x.key, y.key) })
	out := make([]any, len(values))
	for i, item := range items {
		out[i] = item.value
	}
	return out
}

func (r *recordCompare) compareLeaf(path, concrete, typ string, a, b, c any) {
	stats := r.field(path)
	stats.typeName = typ
	eqAB, _ := equalValues(a, b)
	eqAC, formatAC := equalValues(a, c)
	eqBC, _ := equalValues(b, c)
	evidence := func() *Evidence { return r.nodeEvidence(concrete, a, b, c, true, true, true) }
	if r.ignoredValue(path, typ) {
		if !eqAB || !eqAC {
			stats.ignoredValues++
		}
		return
	}
	if eqAB && eqAC && formatAC {
		stats.note(KindNumberFormatChanged, evidence())
	}
	r.tally(stats, eqAB, eqAC, eqBC, evidence)
}

// tally counts one comparison. A candidate equal to either baseline isn't different.
func (r *recordCompare) tally(stats *fieldStats, eqAB, eqAC, eqBC bool, evidence func() *Evidence) {
	stats.observations++
	switch {
	case eqAB && !eqAC:
		stats.candidateStable++
		stats.keepEvidence(KindValueChanged, evidence())
	case !eqAB:
		stats.baselineDisagree++
		stats.keepEvidence(KindNoiseExplained, evidence())
		if !eqAC && !eqBC {
			stats.candidateNoisy++
			stats.keepEvidence(KindValueChanged, evidence())
		}
	}
}

// equalValues compares two values of the same type. formatOnly means two numbers are
// numerically equal but written differently. Numbers aren't converted to floats, which
// would lose precision.
func equalValues(a, b any) (equal, formatOnly bool) {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false, false
		}
		if x == y {
			return true, false
		}
		same := numericEqual(string(x), string(y))
		return same, same
	case string:
		y, ok := b.(string)
		return ok && x == y, false
	case bool:
		y, ok := b.(bool)
		return ok && x == y, false
	case nil:
		return b == nil, false
	case textBody:
		y, ok := b.(textBody)
		return ok && x == y, false
	default:
		return canonical(a) == canonical(b), false
	}
}

func numericEqual(a, b string) bool {
	x, ok := exactNumber(a)
	if !ok {
		return false
	}
	y, ok := exactNumber(b)
	if !ok {
		return false
	}
	return x.Cmp(y) == 0
}

func exactNumber(text string) (*big.Rat, bool) {
	if len(text) > maxExactDigits {
		return nil, false
	}
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		exponent, err := strconv.Atoi(text[i+1:])
		if err != nil || exponent > maxExactExponent || exponent < -maxExactExponent {
			return nil, false
		}
	}
	return new(big.Rat).SetString(text)
}

func canonical(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

var plainKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func pathSegment(key string) string {
	if plainKey.MatchString(key) && len(key) <= maxKeyBytes {
		return "." + key
	}
	limit := min(len(key), maxKeyBytes)
	for limit > 0 && limit < len(key) && key[limit]&0xC0 == 0x80 {
		limit--
	}
	shown := key[:limit]
	if limit < len(key) {
		shown += "..."
	}
	quoted := strconv.Quote(shown)
	return "['" + strings.ReplaceAll(quoted[1:len(quoted)-1], "'", `\'`) + "']"
}

// percentile returns the nearest-rank percentile of sorted values: the smallest value
// with at least p percent of the values at or below it.
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[min(max(rank, 1), len(sorted))-1]
}

// Result returns the comparison so far, in a stable order.
func (c *Comparator) Result() *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := &Result{
		Counts:   make(map[Severity]int),
		Coverage: Coverage{Records: c.records, Compared: c.compared},
		Config:   c.cfg,
	}
	if len(c.notCompared) > 0 {
		result.Coverage.NotCompared = make(map[string]int, len(c.notCompared))
		for reason, n := range c.notCompared {
			result.Coverage.NotCompared[reason] = n
		}
	}

	var findings []Finding
	for route, state := range c.routes {
		for path, stats := range state.fields {
			findings = c.fieldFindings(route, path, stats, findings, result)
		}
		summary := c.routeSummary(route, state, &findings)
		result.Routes = append(result.Routes, summary)
		if state.fieldsDropped > 0 {
			result.Truncated.Fields += state.fieldsDropped
			result.Limited = append(result.Limited, Finding{
				Severity: SeverityUncertain,
				Kind:     KindFieldLimitReached,
				Route:    route,
				Count:    state.fieldsDropped,
				Detail:   fmt.Sprintf("more than %d fields on this route; the rest weren't checked", c.cfg.Limits.MaxFieldsPerRoute),
			})
		}
	}
	c.classifier.mu.Lock()
	overflowed := c.classifier.overflowed
	c.classifier.mu.Unlock()
	if overflowed > 0 {
		result.Truncated.RouteRecords = overflowed
		result.Limited = append(result.Limited, Finding{
			Severity: SeverityUncertain,
			Kind:     KindRouteLimitReached,
			Route:    OtherRoutes,
			Count:    overflowed,
			Detail:   fmt.Sprintf("more than %d routes; other records were grouped together", c.cfg.Limits.MaxRoutes),
		})
	}

	for _, finding := range findings {
		result.Counts[finding.Severity]++
	}
	for _, finding := range result.Limited {
		result.Counts[finding.Severity]++
	}
	compareFinding := func(x, y Finding) int {
		return cmp.Or(
			cmp.Compare(severityRank(x.Severity), severityRank(y.Severity)),
			cmp.Compare(x.Route, y.Route),
			cmp.Compare(x.Path, y.Path),
			cmp.Compare(x.Kind, y.Kind),
		)
	}
	slices.SortFunc(findings, compareFinding)
	slices.SortFunc(result.Limited, compareFinding)
	if len(findings) > c.cfg.Limits.MaxFindings {
		result.Truncated.Findings = len(findings) - c.cfg.Limits.MaxFindings
		findings = findings[:c.cfg.Limits.MaxFindings]
	}
	result.Findings = findings

	slices.SortFunc(result.Noise, func(x, y NoiseDecision) int {
		return cmp.Or(cmp.Compare(x.Route, y.Route), cmp.Compare(x.Path, y.Path))
	})
	if len(result.Noise) > c.cfg.Limits.MaxFindings {
		result.Truncated.Noise = len(result.Noise) - c.cfg.Limits.MaxFindings
		result.Noise = result.Noise[:c.cfg.Limits.MaxFindings]
	}
	slices.SortFunc(result.Ignored, func(x, y IgnoredField) int {
		return cmp.Or(cmp.Compare(x.Route, y.Route), cmp.Compare(x.Path, y.Path))
	})
	slices.SortFunc(result.Routes, func(x, y RouteSummary) int { return cmp.Compare(x.Route, y.Route) })
	return result
}

func (c *Comparator) fieldFindings(route, key string, stats *fieldStats, findings []Finding, result *Result) []Finding {
	path := strings.TrimSuffix(key, "#length")
	add := func(kind Kind, count int, evidence *Evidence) {
		findings = append(findings, Finding{
			Severity:     kindSeverity[kind],
			Kind:         kind,
			Route:        route,
			Path:         path,
			Count:        count,
			Observations: stats.observations,
			Evidence:     evidence,
		})
	}
	for kind, count := range stats.counts {
		add(kind, count, stats.evidence[kind])
	}
	if stats.ignoredValues > 0 {
		result.Ignored = append(result.Ignored, IgnoredField{Route: route, Path: path, Count: stats.ignoredValues})
	}
	if stats.ignoredStructure > 0 {
		result.Ignored = append(result.Ignored, IgnoredField{Route: route, Path: path, Count: stats.ignoredStructure, Structure: true})
	}

	changedKind := KindValueChanged
	if stats.isLength {
		changedKind = KindArrayLengthChanged
	}
	differences := stats.candidateStable + stats.candidateNoisy
	if stats.baselineDisagree == 0 {
		if stats.candidateStable > 0 {
			add(changedKind, stats.candidateStable, stats.evidence[KindValueChanged])
		}
		return findings
	}

	decision := NoiseDecision{
		Route:                 route,
		Path:                  path,
		Type:                  stats.typeName,
		Observations:          stats.observations,
		BaselineDisagreements: stats.baselineDisagree,
		CandidateDifferences:  differences,
		BaselineRate:          float64(stats.baselineDisagree) / float64(stats.observations),
		CandidateRate:         float64(differences) / float64(stats.observations),
	}
	switch {
	case stats.observations < c.cfg.Noise.MinObservations:
		decision.Decision = NoiseInsufficient
		add(KindInsufficientEvidence, stats.baselineDisagree, stats.evidence[KindNoiseExplained])
	case decision.CandidateRate-decision.BaselineRate > c.cfg.Noise.Margin:
		decision.Decision = NoiseExceeded
		add(KindValueChangedBeyondNoise, differences, stats.evidence[KindValueChanged])
	default:
		decision.Decision = NoiseExplained
		add(KindNoiseExplained, stats.baselineDisagree, stats.evidence[KindNoiseExplained])
	}
	result.Noise = append(result.Noise, decision)
	return findings
}

func (c *Comparator) routeSummary(route string, state *routeState, findings *[]Finding) RouteSummary {
	summary := RouteSummary{Route: route, Records: state.records}
	if state.records > 0 {
		summary.BaselineErrorRate = float64(state.baselineErrors) / float64(2*state.records)
		summary.CandidateErrorRate = float64(state.candidateErrors) / float64(state.records)
	}
	increase := (summary.CandidateErrorRate - summary.BaselineErrorRate) * 100
	// Rounded, so that an increase of exactly the limit isn't pushed over by float error.
	if state.records >= c.cfg.ErrorRate.MinRequests && math.Round(increase*1e6)/1e6 > c.cfg.ErrorRate.MaxIncreasePoints {
		*findings = append(*findings, Finding{
			Severity: kindSeverity[KindErrorRateRegression],
			Kind:     KindErrorRateRegression,
			Route:    route,
			Count:    state.candidateErrors,
			Detail:   fmt.Sprintf("candidate %.2f%%, baselines %.2f%%", summary.CandidateErrorRate*100, summary.BaselineErrorRate*100),
		})
	}

	summary.Latency.Samples = state.latencySamples
	if state.latencySamples < c.cfg.Latency.MinSamples {
		summary.Latency.Reason = fmt.Sprintf("fewer than %d comparable samples", c.cfg.Latency.MinSamples)
		return summary
	}
	summary.Latency.Evaluated = true
	var sorted [3][]int64
	for i := range sorted {
		sorted[i] = slices.Sorted(slices.Values(state.latency[i]))
	}
	for _, p := range c.cfg.Latency.Percentiles {
		row := PercentileRow{
			Percentile:      p,
			BaselineAMicros: percentile(sorted[0], p),
			BaselineBMicros: percentile(sorted[1], p),
			CandidateMicros: percentile(sorted[2], p),
		}
		row.ReferenceMicros = max(row.BaselineAMicros, row.BaselineBMicros)
		if row.ReferenceMicros > 0 {
			row.IncreasePercent = float64(row.CandidateMicros-row.ReferenceMicros) / float64(row.ReferenceMicros) * 100
		}
		absolute := float64(row.CandidateMicros-row.ReferenceMicros) / 1000
		if row.IncreasePercent > c.cfg.Latency.MaxIncreasePercent && absolute >= c.cfg.Latency.MinIncreaseMillis {
			row.Regression = true
			*findings = append(*findings, Finding{
				Severity: kindSeverity[KindLatencyRegression],
				Kind:     KindLatencyRegression,
				Route:    route,
				Path:     "p" + strconv.FormatFloat(p, 'f', -1, 64),
				Count:    state.latencySamples,
				Detail:   fmt.Sprintf("candidate %.1fms, slower baseline %.1fms", float64(row.CandidateMicros)/1000, float64(row.ReferenceMicros)/1000),
			})
		}
		summary.Latency.Percentiles = append(summary.Latency.Percentiles, row)
	}
	return summary
}
