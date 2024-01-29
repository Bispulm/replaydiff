package diff

// Severity says how serious a finding is. It doesn't decide whether a build fails,
// which is the job of CI policy.
type Severity string

// Severities, from most to least serious.
const (
	// SeverityBreaking means the candidate's contract changed.
	SeverityBreaking Severity = "breaking"
	// SeverityWarning means behavior changed in a way that may be intended.
	SeverityWarning Severity = "warning"
	// SeverityUncertain means the evidence can't support a conclusion either way.
	// It isn't a pass.
	SeverityUncertain Severity = "uncertain"
	// SeverityInfo means a permitted difference, or noise that was explained.
	SeverityInfo Severity = "info"
)

func severityRank(s Severity) int {
	switch s {
	case SeverityBreaking:
		return 0
	case SeverityWarning:
		return 1
	case SeverityUncertain:
		return 2
	default:
		return 3
	}
}

// Kind names what was found.
type Kind string

// Kinds of finding.
const (
	KindStatusClassChanged          Kind = "status_class_changed"
	KindStatusChanged               Kind = "status_changed"
	KindCandidateCallFailed         Kind = "candidate_call_failed"
	KindBaselineStatusUnstable      Kind = "baseline_status_unstable"
	KindContentTypeChanged          Kind = "content_type_changed"
	KindBaselineContentTypeUnstable Kind = "baseline_content_type_unstable"
	KindBodyRemoved                 Kind = "body_removed"
	KindBodyInvalid                 Kind = "body_invalid"
	KindBodyTypeChanged             Kind = "body_type_changed"
	KindBodyAdded                   Kind = "body_added"
	KindBodyNotCompared             Kind = "body_not_compared"
	KindBaselineBodyUnstable        Kind = "baseline_body_unstable"
	KindFieldRemoved                Kind = "field_removed"
	KindTypeChanged                 Kind = "type_changed"
	KindFieldAdded                  Kind = "field_added"
	KindValueChanged                Kind = "value_changed"
	KindValueChangedBeyondNoise     Kind = "value_changed_beyond_noise"
	KindArrayLengthChanged          Kind = "array_length_changed"
	KindNumberFormatChanged         Kind = "number_format_changed"
	KindNoiseExplained              Kind = "noise_explained"
	KindInsufficientEvidence        Kind = "insufficient_baseline_evidence"
	KindBaselinePresenceUnstable    Kind = "baseline_presence_unstable"
	KindBaselineTypeUnstable        Kind = "baseline_type_unstable"
	KindLatencyRegression           Kind = "latency_regression"
	KindErrorRateRegression         Kind = "error_rate_regression"
	KindFieldLimitReached           Kind = "field_limit_reached"
	KindRouteLimitReached           Kind = "route_limit_reached"
)

var kindSeverity = map[Kind]Severity{
	KindStatusClassChanged:          SeverityBreaking,
	KindCandidateCallFailed:         SeverityBreaking,
	KindBodyRemoved:                 SeverityBreaking,
	KindBodyInvalid:                 SeverityBreaking,
	KindBodyTypeChanged:             SeverityBreaking,
	KindFieldRemoved:                SeverityBreaking,
	KindTypeChanged:                 SeverityBreaking,
	KindStatusChanged:               SeverityWarning,
	KindContentTypeChanged:          SeverityWarning,
	KindValueChanged:                SeverityWarning,
	KindValueChangedBeyondNoise:     SeverityWarning,
	KindArrayLengthChanged:          SeverityWarning,
	KindLatencyRegression:           SeverityWarning,
	KindErrorRateRegression:         SeverityWarning,
	KindBaselineStatusUnstable:      SeverityUncertain,
	KindBaselineContentTypeUnstable: SeverityUncertain,
	KindBaselineBodyUnstable:        SeverityUncertain,
	KindBodyNotCompared:             SeverityUncertain,
	KindInsufficientEvidence:        SeverityUncertain,
	KindBaselinePresenceUnstable:    SeverityUncertain,
	KindBaselineTypeUnstable:        SeverityUncertain,
	KindFieldLimitReached:           SeverityUncertain,
	KindRouteLimitReached:           SeverityUncertain,
	KindFieldAdded:                  SeverityInfo,
	KindBodyAdded:                   SeverityInfo,
	KindNumberFormatChanged:         SeverityInfo,
	KindNoiseExplained:              SeverityInfo,
}

// Value is one target's value in evidence. Present distinguishes a missing field from
// one holding null, which has Type "null".
type Value struct {
	Present bool   `json:"present"`
	Type    string `json:"type,omitempty"`
	Text    string `json:"text,omitempty"`
}

// Evidence is the example of a finding with the lowest sequence number. Values are
// taken from sanitized responses and are bounded in size.
type Evidence struct {
	RecordID  string `json:"record_id"`
	Seq       uint64 `json:"seq"`
	Field     string `json:"field,omitempty"`
	BaselineA Value  `json:"baseline_a"`
	BaselineB Value  `json:"baseline_b"`
	Candidate Value  `json:"candidate"`
}

// Finding is one kind of difference at one place on one route.
type Finding struct {
	Severity Severity `json:"severity"`
	Kind     Kind     `json:"kind"`
	Route    string   `json:"route"`
	// Path is the field with array indexes normalized to [*], or empty when the finding
	// is about the response as a whole.
	Path string `json:"path,omitempty"`
	// Count is how many times it occurred.
	Count int `json:"count"`
	// Observations is how many comparisons of this field were made.
	Observations int       `json:"observations,omitempty"`
	Detail       string    `json:"detail,omitempty"`
	Evidence     *Evidence `json:"evidence,omitempty"`
}

// Noise decisions.
const (
	// NoiseExplained means baseline disagreement accounts for the candidate's differences.
	NoiseExplained = "explained"
	// NoiseExceeded means the candidate differs more than baseline disagreement explains.
	NoiseExceeded = "exceeded"
	// NoiseInsufficient means too few comparisons were made to tell.
	NoiseInsufficient = "insufficient_evidence"
)

// NoiseDecision explains how a field that varies between baselines was treated. It
// applies only to values on this route and of this type. Structure is always checked.
type NoiseDecision struct {
	Route                 string  `json:"route"`
	Path                  string  `json:"path"`
	Type                  string  `json:"type"`
	Decision              string  `json:"decision"`
	Observations          int     `json:"observations"`
	BaselineDisagreements int     `json:"baseline_disagreements"`
	CandidateDifferences  int     `json:"candidate_differences"`
	BaselineRate          float64 `json:"baseline_rate"`
	CandidateRate         float64 `json:"candidate_rate"`
}

// IgnoredField reports differences a configured rule suppressed.
type IgnoredField struct {
	Route string `json:"route"`
	Path  string `json:"path"`
	Count int    `json:"count"`
	// Structure means the rule also suppressed structural differences.
	Structure bool `json:"structure,omitempty"`
}

// PercentileRow compares one latency percentile.
type PercentileRow struct {
	Percentile      float64 `json:"percentile"`
	BaselineAMicros int64   `json:"baseline_a_us"`
	BaselineBMicros int64   `json:"baseline_b_us"`
	CandidateMicros int64   `json:"candidate_us"`
	// ReferenceMicros is the slower baseline, which the candidate is compared with.
	ReferenceMicros int64   `json:"reference_us"`
	IncreasePercent float64 `json:"increase_percent"`
	Regression      bool    `json:"regression,omitempty"`
}

// LatencySummary compares one route's latency. Only records that succeeded on all
// three targets count, and those were sent to all three at the same time.
type LatencySummary struct {
	Samples     int             `json:"samples"`
	Evaluated   bool            `json:"evaluated"`
	Reason      string          `json:"reason,omitempty"`
	Percentiles []PercentileRow `json:"percentiles,omitempty"`
}

// RouteSummary describes one route.
type RouteSummary struct {
	Route   string         `json:"route"`
	Records int            `json:"records"`
	Latency LatencySummary `json:"latency"`
	// BaselineErrorRate and CandidateErrorRate count 5xx responses and failed calls.
	BaselineErrorRate  float64 `json:"baseline_error_rate"`
	CandidateErrorRate float64 `json:"candidate_error_rate"`
}

// Coverage accounts for every record given to the comparator.
type Coverage struct {
	Records     int            `json:"records"`
	Compared    int            `json:"compared"`
	NotCompared map[string]int `json:"not_compared,omitempty"`
}

// Truncated reports what limits left out.
type Truncated struct {
	// Findings and Noise count entries left out of those lists. Counts still includes
	// the findings.
	Findings int `json:"findings,omitempty"`
	Noise    int `json:"noise,omitempty"`
	// Fields counts comparisons of fields beyond the per-route limit, which weren't tracked.
	Fields int `json:"fields,omitempty"`
	// RouteRecords counts records grouped under OtherRoutes.
	RouteRecords int `json:"route_records,omitempty"`
}

// Result is the outcome of a comparison, in a stable order.
type Result struct {
	Counts   map[Severity]int `json:"counts"`
	Coverage Coverage         `json:"coverage"`
	Findings []Finding        `json:"findings,omitempty"`
	// Limited lists limits that were reached. It isn't subject to them.
	Limited   []Finding       `json:"limited,omitempty"`
	Noise     []NoiseDecision `json:"noise,omitempty"`
	Ignored   []IgnoredField  `json:"ignored,omitempty"`
	Routes    []RouteSummary  `json:"routes,omitempty"`
	Truncated Truncated       `json:"truncated,omitzero"`
	// Config is the configuration this comparison used.
	Config *Config `json:"config"`
}
