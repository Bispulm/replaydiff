package redact

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"compress/zlib"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/Bispulm/replaydiff/internal/traffic"
)

// DefaultMaxDecompressedBytes bounds a decompressed body.
const DefaultMaxDecompressedBytes = 8 << 20

// queryPlaceholder replaces redacted query and form values. It needs no
// escaping, so the result is still a well-formed query.
const queryPlaceholder = "REDACTED"

// Location names where in an exchange a rule was applied.
type Location string

// Locations.
const (
	RequestHeader   Location = "request.header"
	RequestTrailer  Location = "request.trailer"
	RequestQuery    Location = "request.query"
	RequestBody     Location = "request.body"
	ResponseHeader  Location = "response.header"
	ResponseTrailer Location = "response.trailer"
	ResponseBody    Location = "response.body"
)

// Reasons a body wasn't stored. These fixed strings are the only explanation
// that reaches logs and records. Parser error text is discarded because it can
// quote the content being parsed.
const (
	ReasonMalformedJSON          = "malformed_json"
	ReasonMalformedForm          = "malformed_form"
	ReasonMalformedCompression   = "malformed_compression"
	ReasonUnsupportedEncoding    = "unsupported_encoding"
	ReasonDecompressedTooLarge   = "decompressed_too_large"
	ReasonUnsupportedContentType = "unsupported_content_type"
)

// mandatoryHeaders are always redacted and can't be configured away.
var mandatoryHeaders = []string{
	"Authorization",
	"Cookie",
	"Set-Cookie",
	"X-Api-Key",
	"Proxy-Authorization",
}

// sensitiveNameParts redact any header whose lower-cased name contains one of
// them. This over-matches on purpose: the cost is less replay fidelity, and
// the alternative is storing a credential under an unforeseen name.
var sensitiveNameParts = []string{
	"auth",
	"token",
	"secret",
	"password",
	"passwd",
	"credential",
	"session",
	"cookie",
	"api-key",
	"apikey",
	"api_key",
}

// hopByHopHeaders describe one connection, so they aren't part of the exchange.
var hopByHopHeaders = map[string]bool{
	"Connection":         true,
	"Keep-Alive":         true,
	"Proxy-Connection":   true,
	"Proxy-Authenticate": true,
	"Te":                 true,
	"Trailer":            true,
	"Transfer-Encoding":  true,
	"Upgrade":            true,
}

// bodyDerivedHeaders describe the original bytes rather than the stored ones.
// A stored digest could also be used to confirm guesses at a redacted value.
var bodyDerivedHeaders = map[string]bool{
	"Content-Length":   true,
	"Content-Encoding": true,
	"Content-Md5":      true,
	"Digest":           true,
	"Content-Digest":   true,
	"Repr-Digest":      true,
	"Etag":             true,
}

// urlHeaders hold a URL whose query the query rules also cover.
var urlHeaders = map[string]bool{
	"Referer":          true,
	"Location":         true,
	"Content-Location": true,
}

// Hits counts rule applications for one record. Its zero value is ready to use.
// It isn't safe for concurrent use.
type Hits struct {
	counts map[hitKey]int
}

type hitKey struct {
	location Location
	rule     string
}

func (h *Hits) add(location Location, rule string, n int) {
	if n == 0 {
		return
	}
	if h.counts == nil {
		h.counts = make(map[hitKey]int)
	}
	h.counts[hitKey{location, rule}] += n
}

// List returns the hits in a stable order.
func (h *Hits) List() []traffic.RedactionHit {
	if len(h.counts) == 0 {
		return nil
	}
	out := make([]traffic.RedactionHit, 0, len(h.counts))
	for key, count := range h.counts {
		out = append(out, traffic.RedactionHit{Location: string(key.location), Rule: key.rule, Count: count})
	}
	slices.SortFunc(out, func(a, b traffic.RedactionHit) int {
		return cmp.Or(cmp.Compare(a.Location, b.Location), cmp.Compare(a.Rule, b.Rule))
	})
	return out
}

// Options configures an Engine.
type Options struct {
	// MaxDecompressedBytes bounds a decompressed body. Zero selects
	// DefaultMaxDecompressedBytes.
	MaxDecompressedBytes int64
	// SessionSecret keys session digests. Nil generates a random secret, which
	// limits correlation to the engine's lifetime.
	SessionSecret []byte
}

// Engine applies a Policy. It is safe for concurrent use.
type Engine struct {
	policyDigest    string
	headers         map[string]string
	queryParams     map[string]string
	jsonPaths       []*jsonPath
	opaqueTypes     map[string]bool
	sessionSources  [][2]string
	sessionSecret   []byte
	maxDecompressed int64
	zdec            *zstd.Decoder
}

// NewEngine compiles a policy. Close releases its resources.
func NewEngine(policy *Policy, opts Options) (*Engine, error) {
	if err := policy.validate(); err != nil {
		return nil, fmt.Errorf("invalid redaction policy: %w", err)
	}
	e := &Engine{
		policyDigest:    policy.Digest(),
		headers:         make(map[string]string),
		queryParams:     make(map[string]string, len(policy.QueryParams)),
		opaqueTypes:     make(map[string]bool, len(policy.OpaqueContentTypes)),
		sessionSecret:   opts.SessionSecret,
		maxDecompressed: cmp.Or(opts.MaxDecompressedBytes, DefaultMaxDecompressedBytes),
	}
	for _, name := range policy.Headers {
		e.headers[http.CanonicalHeaderKey(name)] = name
	}
	for _, name := range mandatoryHeaders {
		e.headers[name] = name
	}
	for _, name := range policy.QueryParams {
		e.queryParams[strings.ToLower(name)] = name
	}
	for _, text := range policy.JSONPaths {
		path, err := parseJSONPath(text)
		if err != nil {
			return nil, err
		}
		e.jsonPaths = append(e.jsonPaths, path)
	}
	for _, contentType := range policy.OpaqueContentTypes {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return nil, fmt.Errorf("invalid opaque content type: %w", err)
		}
		e.opaqueTypes[mediaType] = true
	}
	for _, source := range policy.Session.Sources {
		kind, name, err := parseSessionSource(source)
		if err != nil {
			return nil, err
		}
		e.sessionSources = append(e.sessionSources, [2]string{kind, name})
	}
	if len(e.sessionSecret) == 0 {
		e.sessionSecret = make([]byte, 32)
		if _, err := rand.Read(e.sessionSecret); err != nil {
			return nil, fmt.Errorf("generate session secret: %w", err)
		}
	}
	zdec, err := zstd.NewReader(nil,
		zstd.WithDecoderMaxMemory(uint64(e.maxDecompressed)), //nolint:gosec // Positive by construction.
		zstd.WithDecoderConcurrency(0),
	)
	if err != nil {
		return nil, fmt.Errorf("create decompressor: %w", err)
	}
	e.zdec = zdec
	return e, nil
}

// Close releases the engine's resources.
func (e *Engine) Close() { e.zdec.Close() }

// PolicyDigest identifies the policy this engine applies.
func (e *Engine) PolicyDigest() string { return e.policyDigest }

// Headers returns a sanitized copy of h, with canonical names.
func (e *Engine) Headers(location Location, h http.Header, hits *Hits) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	connectionScoped := make(map[string]bool)
	for name, values := range h {
		if http.CanonicalHeaderKey(name) != "Connection" {
			continue
		}
		for _, value := range values {
			for _, token := range strings.Split(value, ",") {
				connectionScoped[http.CanonicalHeaderKey(strings.TrimSpace(token))] = true
			}
		}
	}

	out := make(map[string][]string, len(h))
	for rawName, values := range h {
		name := http.CanonicalHeaderKey(rawName)
		if hopByHopHeaders[name] || connectionScoped[name] || bodyDerivedHeaders[name] {
			continue
		}
		if rule := e.headerRule(name); rule != "" {
			out[name] = []string{Placeholder}
			hits.add(location, rule, len(values))
			continue
		}
		for _, value := range values {
			out[name] = append(out[name], e.headerValue(location, name, value, hits))
		}
	}
	return out
}

func (e *Engine) headerRule(name string) string {
	if rule, ok := e.headers[name]; ok {
		return rule
	}
	lower := strings.ToLower(name)
	for _, part := range sensitiveNameParts {
		if strings.Contains(lower, part) {
			return "name-contains:" + part
		}
	}
	return ""
}

func (e *Engine) headerValue(location Location, name, value string, hits *Hits) string {
	switch {
	case urlHeaders[name]:
		return e.urlValue(location, value, hits)
	case name == "Link" && strings.ContainsRune(value, '?'):
		// A Link value can hold several URLs in a syntax of its own, so it
		// isn't taken apart.
		hits.add(location, "url-with-query", 1)
		return Placeholder
	}
	return value
}

func (e *Engine) urlValue(location Location, value string, hits *Hits) string {
	u, err := url.Parse(value)
	if err != nil {
		hits.add(location, "unparsable-url", 1)
		return Placeholder
	}
	u.RawQuery = e.params(location, u.RawQuery, hits)
	if fragment := u.EscapedFragment(); fragment != "" {
		if sanitized := e.params(location, fragment, hits); sanitized != fragment {
			u.RawFragment = ""
			u.Fragment = sanitized
		}
	}
	return u.String()
}

// Query sanitizes a raw query string, keeping parameter order and separators.
func (e *Engine) Query(raw string, hits *Hits) string {
	return e.params(RequestQuery, raw, hits)
}

// params sanitizes key=value pairs. Names are matched after decoding and
// regardless of case. A pair with a malformed escape is masked, since servers
// disagree about what it decodes to and it can't be matched reliably.
func (e *Engine) params(location Location, raw string, hits *Hits) string {
	if raw == "" {
		return ""
	}
	var out strings.Builder
	out.Grow(len(raw))
	rest := raw
	for {
		end := strings.IndexAny(rest, "&;")
		pair := rest
		if end >= 0 {
			pair = rest[:end]
		}
		out.WriteString(e.param(location, pair, hits))
		if end < 0 {
			return out.String()
		}
		out.WriteByte(rest[end])
		rest = rest[end+1:]
	}
}

func (e *Engine) param(location Location, pair string, hits *Hits) string {
	rawName, rawValue, hasValue := strings.Cut(pair, "=")
	name, nameErr := url.QueryUnescape(rawName)
	value, valueErr := url.QueryUnescape(rawValue)

	// The name itself is normally kept. These two cases are where it can hold a
	// covered value, so it has to go as well.
	if nameErr != nil {
		hits.add(location, "malformed-parameter", 1)
		return queryPlaceholder + "=" + queryPlaceholder
	}
	if rule := e.nestedParameter(name); rule != "" {
		hits.add(location, "nested:"+rule, 1)
		return queryPlaceholder + "=" + queryPlaceholder
	}

	if valueErr != nil {
		hits.add(location, "malformed-parameter", 1)
		return rawName + "=" + queryPlaceholder
	}
	if !hasValue {
		return pair
	}
	if rule, ok := e.queryParams[strings.ToLower(name)]; ok {
		hits.add(location, rule, 1)
		return rawName + "=" + queryPlaceholder
	}
	if rule := e.nestedParameter(name + "=" + value); rule != "" {
		hits.add(location, "nested:"+rule, 1)
		return rawName + "=" + queryPlaceholder
	}
	return pair
}

// nestedParameter finds a listed parameter inside a decoded pair. This catches
// redirect targets, malformed URLs and hash-routed paths, where the parameter
// isn't the pair's own name. It also matches names merely ending in a listed
// one, which over-redacts rather than risks missing a value.
func (e *Engine) nestedParameter(pair string) string {
	lower := strings.ToLower(pair)
	for name, rule := range e.queryParams {
		if strings.Contains(lower, name+"=") {
			return rule
		}
	}
	return ""
}

// BodyInput is a complete body as observed on the wire.
type BodyInput struct {
	ContentType     string
	ContentEncoding string
	Data            []byte
}

// BodyResult is a sanitized body.
type BodyResult struct {
	Body traffic.Body
	// Failed means the body should have been sanitizable and wasn't. Having no
	// rule for a content type isn't a failure.
	Failed bool
}

type bodyKind int

const (
	bodyUnsupported bodyKind = iota
	bodyJSON
	bodyForm
	bodyOpaque
)

// Body sanitizes a complete body. Every path that can't produce a sanitized
// body returns one with no data. No path stores the original as a fallback.
func (e *Engine) Body(location Location, in BodyInput, hits *Hits) BodyResult {
	body := traffic.Body{ObservedBytes: int64(len(in.Data))}
	if len(in.Data) == 0 {
		body.State = traffic.BodyEmpty
		return BodyResult{Body: body}
	}

	mediaType, kind := e.classify(in.ContentType)
	body.ContentType = mediaType
	omit := func(reason string, failed bool) BodyResult {
		body.State = traffic.BodyOmitted
		body.Reason = reason
		return BodyResult{Body: body, Failed: failed}
	}
	if kind == bodyUnsupported {
		return omit(ReasonUnsupportedContentType, false)
	}

	encoding := strings.ToLower(strings.TrimSpace(in.ContentEncoding))
	if encoding != "" && encoding != "identity" {
		body.OriginalEncoding = encoding
	}
	data, reason := e.decompress(encoding, in.Data)
	if reason != "" {
		return omit(reason, true)
	}
	if len(data) == 0 {
		body.State = traffic.BodyEmpty
		return BodyResult{Body: body}
	}

	var sanitized []byte
	switch kind {
	case bodyJSON:
		var err error
		sanitized, err = e.sanitizeJSON(location, data, hits)
		if err != nil {
			return omit(ReasonMalformedJSON, true)
		}
	case bodyForm:
		sanitized = []byte(e.params(location, string(data), hits))
	case bodyOpaque:
		sanitized = data
	case bodyUnsupported:
		return omit(ReasonUnsupportedContentType, false)
	}
	body.State = traffic.BodyPresent
	body.Data = sanitized
	return BodyResult{Body: body}
}

func (e *Engine) classify(contentType string) (string, bodyKind) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	switch {
	case err != nil:
		return "", bodyUnsupported
	case isJSONType(mediaType):
		return mediaType, bodyJSON
	case mediaType == formMediaType:
		return mediaType, bodyForm
	case e.opaqueTypes[mediaType]:
		return mediaType, bodyOpaque
	default:
		return mediaType, bodyUnsupported
	}
}

// decompress returns the decoded body, or a reason it can't be decoded. Output
// is limited while reading, so a small hostile body can't exhaust memory.
func (e *Engine) decompress(encoding string, data []byte) ([]byte, string) {
	switch encoding {
	case "", "identity":
		return data, ""
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, ReasonMalformedCompression
		}
		return e.readLimited(r)
	case "deflate":
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, ReasonMalformedCompression
		}
		return e.readLimited(r)
	case "zstd":
		out, err := e.zdec.DecodeAll(data, nil)
		switch {
		case errors.Is(err, zstd.ErrDecoderSizeExceeded), errors.Is(err, zstd.ErrWindowSizeExceeded):
			return nil, ReasonDecompressedTooLarge
		case err != nil:
			return nil, ReasonMalformedCompression
		}
		return out, ""
	default:
		return nil, ReasonUnsupportedEncoding
	}
}

func (e *Engine) readLimited(r io.ReadCloser) ([]byte, string) {
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(io.LimitReader(r, e.maxDecompressed+1))
	switch {
	case err != nil:
		return nil, ReasonMalformedCompression
	case int64(len(out)) > e.maxDecompressed:
		return nil, ReasonDecompressedTooLarge
	}
	return out, ""
}

// sanitizeJSON parses the body, applies the rules to the tree and re-encodes
// it. Storing the re-encoded tree rather than patching the original bytes means
// duplicate keys and escaped names can't hide a value from a rule. Numbers keep
// their exact text.
func (e *Engine) sanitizeJSON(location Location, data []byte, hits *Hits) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	for _, path := range e.jsonPaths {
		var count int
		root, count = path.apply(root)
		hits.add(location, path.text, count)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// SessionKey returns a keyed digest of the first configured session source
// that has a value, or "" if none does. The source is part of the digest, so
// the same value under two sources isn't treated as one session.
func (e *Engine) SessionKey(h http.Header, rawQuery string) string {
	for _, source := range e.sessionSources {
		value := sessionValue(source[0], source[1], h, rawQuery)
		if value == "" {
			continue
		}
		mac := hmac.New(sha256.New, e.sessionSecret)
		mac.Write([]byte("replaydiff/session/v1\x00"))
		mac.Write([]byte(source[0] + ":" + source[1] + "\x00"))
		mac.Write([]byte(value))
		return hex.EncodeToString(mac.Sum(nil)[:16])
	}
	return ""
}

func sessionValue(kind, name string, h http.Header, rawQuery string) string {
	switch kind {
	case "header":
		return h.Get(name)
	case "cookie":
		cookie, err := (&http.Request{Header: h}).Cookie(name)
		if err != nil {
			return ""
		}
		return cookie.Value
	case "query":
		for _, pair := range strings.FieldsFunc(rawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
			rawName, rawValue, _ := strings.Cut(pair, "=")
			decoded, err := url.QueryUnescape(rawName)
			if err != nil || !strings.EqualFold(decoded, name) {
				continue
			}
			if value, err := url.QueryUnescape(rawValue); err == nil {
				return value
			}
		}
	}
	return ""
}
