package metrics

import (
	"math"
	"strings"
	"testing"
)

func TestWriterGroupsFamilies(t *testing.T) {
	w := New()
	w.Gauge("node64_check_up", "Check erreichbar", 1, "check", "Web")
	w.Counter("node64_requests_total", "Anfragen", 5)
	w.Gauge("node64_check_up", "anderer Text wird ignoriert", 0, "check", `a"b\c`+"\n")
	w.Gauge("bad name", "", 1)                      // ungueltiger Name
	w.Gauge("node64_x", "", 1, "only-key")          // ungerade Labels
	w.Counter("node64_check_up", "falscher Typ", 1) // Typwechsel
	w.Gauge("node64_nan", "", math.NaN())
	var b strings.Builder
	if _, err := w.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP node64_check_up Check erreichbar
# TYPE node64_check_up gauge
node64_check_up{check="Web"} 1
node64_check_up{check="a\"b\\c\n"} 0
# HELP node64_requests_total Anfragen
# TYPE node64_requests_total counter
node64_requests_total 5
# TYPE node64_nan gauge
node64_nan NaN
`
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestFormatValue(t *testing.T) {
	for v, s := range map[float64]string{0: "0", 1.5: "1.5", 1e15: "1e+15", 123456: "123456", math.Inf(1): "+Inf"} {
		if got := formatValue(v); got != s {
			t.Errorf("%v: %q, want %q", v, got, s)
		}
	}
}
