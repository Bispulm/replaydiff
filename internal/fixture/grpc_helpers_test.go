package fixture

import (
	"encoding/json"
	"io"
	"reflect"
)

var errEOF = io.EOF

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func equalExcept(a, b map[string]any, keys ...string) bool {
	return reflect.DeepEqual(without(a, keys...), without(b, keys...))
}
