// Package redact sanitizes captured traffic before it is persisted. See
// docs/redaction.md for what it covers and, just as importantly, what it can't.
package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Policy is the operator's redaction configuration. The mandatory header rules
// always apply in addition to it and can't be turned off.
type Policy struct {
	Headers     []string `yaml:"headers" json:"headers,omitempty"`
	QueryParams []string `yaml:"query_params" json:"query_params,omitempty"`
	JSONPaths   []string `yaml:"json_paths" json:"json_paths,omitempty"`
	ProtoFields []string `yaml:"proto_fields" json:"proto_fields,omitempty"`
	// OpaqueContentTypes lists media types stored without inspection. Rules
	// can't apply to them, so each entry is an explicit acceptance of that.
	OpaqueContentTypes []string      `yaml:"opaque_content_types" json:"opaque_content_types,omitempty"`
	Session            SessionPolicy `yaml:"session" json:"session"`
}

// SessionPolicy names where a session identifier can be found.
type SessionPolicy struct {
	// Sources are tried in order. Each has the form cookie:NAME, header:NAME
	// or query:NAME.
	Sources []string `yaml:"sources" json:"sources,omitempty"`
}

// LoadPolicy reads and validates a policy file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path) //nolint:gosec // The path is the operator's own flag.
	if err != nil {
		return nil, fmt.Errorf("read redaction policy: %w", err)
	}
	return ParsePolicy(data)
}

// ParsePolicy decodes and validates a policy. Unknown keys are errors, because
// a misspelled rule that was ignored would silently leave data unredacted.
func ParsePolicy(data []byte) (*Policy, error) {
	var policy Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse redaction policy: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse redaction policy: expected a single document")
	}
	if err := policy.validate(); err != nil {
		return nil, fmt.Errorf("invalid redaction policy: %w", err)
	}
	return &policy, nil
}

func (p *Policy) validate() error {
	if len(p.ProtoFields) > 0 {
		return errors.New("proto_fields isn't supported yet: refusing to accept rules that wouldn't be applied")
	}
	for _, name := range p.Headers {
		if strings.TrimSpace(name) == "" {
			return errors.New("headers: empty name")
		}
	}
	for _, name := range p.QueryParams {
		if strings.TrimSpace(name) == "" {
			return errors.New("query_params: empty name")
		}
	}
	for _, path := range p.JSONPaths {
		if _, err := parseJSONPath(path); err != nil {
			return fmt.Errorf("json_paths: %w", err)
		}
	}
	for _, source := range p.Session.Sources {
		if _, _, err := parseSessionSource(source); err != nil {
			return fmt.Errorf("session.sources: %w", err)
		}
	}
	for _, contentType := range p.OpaqueContentTypes {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return fmt.Errorf("opaque_content_types: invalid media type %q", contentType)
		}
		if isJSONType(mediaType) || mediaType == formMediaType {
			return fmt.Errorf("opaque_content_types: %q has redaction rules and can't be opaque", contentType)
		}
	}
	return nil
}

// Digest identifies the policy's rules, so a report can show which policy
// sanitized a dataset.
func (p *Policy) Digest() string {
	data, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

func parseSessionSource(source string) (kind, name string, err error) {
	kind, name, ok := strings.Cut(source, ":")
	if !ok || name == "" {
		return "", "", fmt.Errorf("source %q must have the form kind:name", source)
	}
	switch kind {
	case "cookie", "header", "query":
		return kind, name, nil
	default:
		return "", "", fmt.Errorf("source %q: kind must be cookie, header or query", source)
	}
}

const formMediaType = "application/x-www-form-urlencoded"

func isJSONType(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// IsJSONType reports whether bodies of a media type are parsed as JSON. A body sanitized
// as JSON is known to hold exactly one valid value.
func IsJSONType(mediaType string) bool { return isJSONType(mediaType) }
