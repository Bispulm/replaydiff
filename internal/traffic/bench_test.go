package traffic

import (
	"strings"
	"testing"
)

func BenchmarkEncodeRecord(b *testing.B) {
	enc, err := NewEncoder(EncoderOptions{})
	if err != nil {
		b.Fatal(err)
	}
	defer enc.Close()
	rec := validRecord()
	body := `{"id":"ord-1","items":[` + strings.Repeat(`{"sku":"sku-1","qty":2},`, 40) + `{"sku":"sku-2","qty":1}]}`
	rec.Response.Body = Body{State: BodyPresent, ContentType: "application/json", Data: []byte(body)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := enc.Encode(rec); err != nil {
			b.Fatal(err)
		}
	}
}
