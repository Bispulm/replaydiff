// Package replay sends recorded requests to two baselines and a candidate.
//
// Safety comes first. Destinations come only from validated configuration, never
// from a record. Only read-only methods are eligible unless explicitly allowed.
// Redirects aren't followed, and nothing is retried: one record means exactly one
// call per target.
package replay

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults for zero Config values.
const (
	DefaultConcurrency          = 32
	DefaultPerTargetConcurrency = 16
	DefaultMaxActiveSessions    = 256
	DefaultTimeout              = 10 * time.Second
	DefaultMaxResponseBytes     = 8 << 20
)

// TargetConfig names one replay destination.
type TargetConfig struct {
	// URL is an origin: scheme, host and optional port, with nothing else.
	URL string
	// Headers are added to every call to this target, overriding anything from
	// the record. This is how per-target credentials are supplied. They never
	// come from recordings.
	Headers http.Header
}

// Config configures an Engine.
type Config struct {
	BaselineA TargetConfig
	BaselineB TargetConfig
	Candidate TargetConfig
	// AllowedOrigins must contain every target's origin. It is separate from the
	// targets so that a mistyped target fails rather than sending traffic.
	AllowedOrigins []string
	// AllowMethods adds methods beyond GET, HEAD and OPTIONS. Replaying a
	// mutating request repeats its side effects on all three targets.
	AllowMethods []string

	// Concurrency limits in-flight upstream calls across all targets.
	Concurrency int
	// PerTargetConcurrency limits in-flight upstream calls to each target.
	PerTargetConcurrency int
	// MaxActiveSessions limits sessions being worked on at once. Others wait.
	MaxActiveSessions int
	// RecordsPerSecond limits logical records started per second, and each one
	// makes three upstream calls. Zero means no limit.
	RecordsPerSecond float64
	// TargetCallsPerSecond limits calls per second to each target. Zero means no
	// limit.
	TargetCallsPerSecond float64
	// Timeout limits one upstream call, including reading its response.
	Timeout time.Duration
	// MaxResponseBytes limits a held response body, after decompression.
	MaxResponseBytes int64
}

func (c Config) withDefaults() Config {
	c.Concurrency = cmp.Or(c.Concurrency, DefaultConcurrency)
	c.PerTargetConcurrency = cmp.Or(c.PerTargetConcurrency, DefaultPerTargetConcurrency)
	c.MaxActiveSessions = cmp.Or(c.MaxActiveSessions, DefaultMaxActiveSessions)
	c.Timeout = cmp.Or(c.Timeout, DefaultTimeout)
	c.MaxResponseBytes = cmp.Or(c.MaxResponseBytes, DefaultMaxResponseBytes)
	return c
}

func (c Config) validateLimits() error {
	switch {
	case c.Concurrency < 0, c.PerTargetConcurrency < 0, c.MaxActiveSessions < 0:
		return errors.New("replay: concurrency limits must not be negative")
	case c.RecordsPerSecond < 0, c.TargetCallsPerSecond < 0:
		return errors.New("replay: rate limits must not be negative")
	case c.Timeout < 0, c.MaxResponseBytes < 0:
		return errors.New("replay: timeout and response limit must not be negative")
	}
	return nil
}

// TargetNotAllowedError means a target's origin isn't on the allowlist.
type TargetNotAllowedError struct {
	Role   string
	Origin string
}

func (e *TargetNotAllowedError) Error() string {
	return fmt.Sprintf("replay: %s origin %s is not on the allowlist", e.Role, e.Origin)
}

// parseOrigin validates a URL and returns its normalized origin. Errors never
// echo the input, since it may hold credentials. Default ports are removed and
// the host is lower-cased, so equivalent spellings compare equal. The host is
// compared as text: see docs/replay.md for what that assumes about DNS.
func parseOrigin(raw string) (string, *url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case raw == "":
		return "", nil, errors.New("URL is required")
	case err != nil:
		return "", nil, errors.New("not a valid URL")
	case u.Scheme != "http" && u.Scheme != "https":
		return "", nil, errors.New("scheme must be http or https")
	case u.Hostname() == "":
		return "", nil, errors.New("host is required")
	case u.User != nil:
		return "", nil, errors.New("credentials aren't allowed in the URL; use per-target headers")
	case u.Path != "" && u.Path != "/":
		return "", nil, errors.New("a path isn't allowed: a target is an origin")
	case u.RawQuery != "" || u.Fragment != "":
		return "", nil, errors.New("a query or fragment isn't allowed")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	address := host
	switch {
	case port != "":
		address = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		address = "[" + host + "]"
	}
	return u.Scheme + "://" + address, &url.URL{Scheme: u.Scheme, Host: address}, nil
}

// neverAllowedMethods can't be opted into. CONNECT would turn the replayer into
// a tunnel, and TRACE echoes the request back into results.
var neverAllowedMethods = map[string]bool{http.MethodConnect: true, http.MethodTrace: true}

func allowedMethods(extra []string) (map[string]bool, error) {
	allowed := map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodOptions: true}
	for _, method := range extra {
		upper := strings.ToUpper(method)
		if neverAllowedMethods[upper] {
			return nil, fmt.Errorf("replay: method %s can't be allowed", upper)
		}
		allowed[upper] = true
	}
	return allowed, nil
}

func validateTargetHeaders(role string, headers http.Header) error {
	for name, values := range headers {
		if !validHeaderName(name) {
			return fmt.Errorf("replay: %s has an invalid header name", role)
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n\x00") {
				return fmt.Errorf("replay: %s header %s has an invalid value", role, name)
			}
		}
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
