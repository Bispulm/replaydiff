package diff

import (
	"strconv"
	"strings"
	"testing"
)

func BenchmarkObserveJSONRecord(b *testing.B) {
	comparator := newComparator(b, "", "")
	body := func(time string) string {
		return `{"id":"ord-1","server_time":"` + time + `","items":[` + strings.Repeat(`{"sku":"sku-1","qty":2},`, 40) + `{"sku":"sku-2","qty":1}]}`
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		comparator.Observe(record(i, "GET", "/v1/orders/ord-1", jsonReply(body("a"+strconv.Itoa(i))), jsonReply(body("b"+strconv.Itoa(i))), jsonReply(body("c"+strconv.Itoa(i)))))
	}
}
