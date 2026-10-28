package peer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/wire"
)

// Eine Seite bleibt unter measBytes; der letzte enthaltene Messpunkt wird zum Stand.
func TestFitMeasPage(t *testing.T) {
	big := strings.Repeat("x", 20<<10)
	out := measOut{Last: 1000, Head: 1000}
	for i := 1; i <= 1000; i++ {
		out.Items = append(out.Items, wire.Measurement{Seq: int64(i), Token: "t", Details: map[string]any{"body": big}})
	}
	fitMeasPage(&out)
	b, _ := json.Marshal(out)
	if len(b) > measBytes || !out.More || len(out.Items) == 0 || out.Last != out.Items[len(out.Items)-1].Seq {
		t.Fatalf("page: %d bytes, %d items, last %d, more %v", len(b), len(out.Items), out.Last, out.More)
	}
	small := measOut{Last: 7, Items: []wire.Measurement{{Seq: 5}}}
	fitMeasPage(&small)
	if small.Last != 7 || small.More || len(small.Items) != 1 {
		t.Fatalf("small page changed: %+v", small)
	}
}
