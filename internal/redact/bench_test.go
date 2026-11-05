package redact

import (
	"strconv"
	"strings"
	"testing"
)

// jsonOf returns a JSON object of roughly size bytes, with fields a policy covers.
func jsonOf(size int) []byte {
	var b strings.Builder
	b.WriteString(`{"user":{"email":"someone@example.test","name":"Someone"},"items":[`)
	for i := 0; b.Len() < size; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"sku":"sku-` + strconv.Itoa(i) + `","card":"4242424242424242","qty":2}`)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

func BenchmarkJSONBody(b *testing.B) {
	engine := newEngine(b, `json_paths: ["$.user.email", "$.items[*].card"]`)
	for _, size := range []int{1 << 10, 64 << 10} {
		data := jsonOf(size)
		b.Run(strconv.Itoa(size>>10)+"KiB", func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				engine.Body(ResponseBody, BodyInput{ContentType: "application/json", Data: data}, &Hits{})
			}
		})
	}
}
