package redact

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Placeholder replaces every redacted JSON value and header value.
const Placeholder = "[REDACTED]"

type segmentKind int

const (
	segmentKey segmentKind = iota
	segmentIndex
	segmentWildcard
	segmentRecursive
)

type pathSegment struct {
	kind  segmentKind
	name  string
	index int
}

// jsonPath is a parsed path expression. docs/redaction.md specifies the
// supported syntax, which is a deliberately small subset of JSONPath: paths
// that can't be parsed are refused at startup rather than ignored.
type jsonPath struct {
	text     string
	segments []pathSegment
}

func parseJSONPath(text string) (*jsonPath, error) {
	invalid := func(why string) (*jsonPath, error) {
		return nil, fmt.Errorf("invalid JSON path %q: %s", text, why)
	}
	if !strings.HasPrefix(text, "$") {
		return invalid("must start with $")
	}
	path := &jsonPath{text: text}
	rest := text[1:]
	for rest != "" {
		var (
			seg pathSegment
			err error
		)
		switch {
		case strings.HasPrefix(rest, ".."):
			seg, rest, err = parseRecursive(rest[2:])
		case strings.HasPrefix(rest, "."):
			seg, rest, err = parseMember(rest[1:])
		case strings.HasPrefix(rest, "["):
			seg, rest, err = parseBracket(rest)
		default:
			err = errors.New("expected '.' or '['")
		}
		if err != nil {
			return invalid(err.Error())
		}
		path.segments = append(path.segments, seg)
	}
	return path, nil
}

func parseMember(s string) (pathSegment, string, error) {
	if strings.HasPrefix(s, "*") {
		return pathSegment{kind: segmentWildcard}, s[1:], nil
	}
	name, rest := takeName(s)
	if name == "" {
		return pathSegment{}, "", errors.New("expected a member name")
	}
	return pathSegment{kind: segmentKey, name: name}, rest, nil
}

func parseRecursive(s string) (pathSegment, string, error) {
	if strings.HasPrefix(s, "['") {
		seg, rest, err := parseBracket(s)
		if err != nil {
			return pathSegment{}, "", err
		}
		seg.kind = segmentRecursive
		return seg, rest, nil
	}
	name, rest := takeName(s)
	if name == "" {
		return pathSegment{}, "", errors.New("recursive descent needs a member name")
	}
	return pathSegment{kind: segmentRecursive, name: name}, rest, nil
}

func parseBracket(s string) (pathSegment, string, error) {
	switch {
	case strings.HasPrefix(s, "[*]"):
		return pathSegment{kind: segmentWildcard}, s[3:], nil
	case strings.HasPrefix(s, "['"):
		end := strings.Index(s, "']")
		if end < 2 {
			return pathSegment{}, "", errors.New("unterminated quoted name")
		}
		return pathSegment{kind: segmentKey, name: s[2:end]}, s[end+2:], nil
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return pathSegment{}, "", errors.New("unterminated bracket")
	}
	index, err := strconv.Atoi(s[1:end])
	if err != nil || index < 0 {
		return pathSegment{}, "", errors.New("bracket must hold a non-negative index, * or a quoted name")
	}
	return pathSegment{kind: segmentIndex, index: index}, s[end+1:], nil
}

func takeName(s string) (name, rest string) {
	i := 0
	for i < len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			i++
			continue
		}
		break
	}
	return s[:i], s[i:]
}

// apply replaces matches in a tree decoded by encoding/json and returns the
// new root with the number of values replaced. Keys match case-insensitively:
// many decoders do, so an exact match could miss a value the service honors.
// Over-matching costs comparison detail, and under-matching leaks data.
func (p *jsonPath) apply(root any) (any, int) {
	count := 0
	out := applySegments(root, p.segments, &count)
	return out, count
}

func applySegments(node any, segments []pathSegment, count *int) any {
	if len(segments) == 0 {
		*count++
		return Placeholder
	}
	seg, rest := segments[0], segments[1:]
	switch seg.kind {
	case segmentKey:
		if object, ok := node.(map[string]any); ok {
			for key, value := range object {
				if strings.EqualFold(key, seg.name) {
					object[key] = applySegments(value, rest, count)
				}
			}
		}
	case segmentIndex:
		if array, ok := node.([]any); ok && seg.index < len(array) {
			array[seg.index] = applySegments(array[seg.index], rest, count)
		}
	case segmentWildcard:
		switch container := node.(type) {
		case map[string]any:
			for key, value := range container {
				container[key] = applySegments(value, rest, count)
			}
		case []any:
			for i, value := range container {
				container[i] = applySegments(value, rest, count)
			}
		}
	case segmentRecursive:
		switch container := node.(type) {
		case map[string]any:
			for key, value := range container {
				if strings.EqualFold(key, seg.name) {
					if len(rest) == 0 {
						container[key] = applySegments(value, nil, count)
						continue
					}
					value = applySegments(value, rest, count)
				}
				container[key] = applySegments(value, segments, count)
			}
		case []any:
			for i, value := range container {
				container[i] = applySegments(value, segments, count)
			}
		}
	}
	return node
}
