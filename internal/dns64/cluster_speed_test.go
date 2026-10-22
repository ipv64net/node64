package dns64

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Tausende Eintraege ueber den Cluster: liefern aus dem gemeldeten Stand, uebernehmen per SQL mit gebuendeltem
// Neuaufbau (frueher je Eintrag alles neu gelesen und berechnet: 3000 Eintraege rund 45 s).
func TestClusterManyRecords(t *testing.T) {
	a, _ := testModule(t)
	b, _ := testModule(t)
	ctx := context.Background()
	var sb strings.Builder
	for k := 0; k < 3000; k++ {
		fmt.Fprintf(&sb, "10.100.%d.%d host%d.bulk.lan\n", k/250, k%250+1, k)
	}
	var la clLog
	a.SetCluster(la.hook)
	b.SetCluster(func(context.Context, string, string, bool) {})
	if _, err := a.ImportRecords(ctx, sb.String()); err != nil {
		t.Fatal(err)
	}
	calls := la.take()
	if len(calls) != 3000 {
		t.Fatalf("reported %d changes", len(calls))
	}
	start := time.Now()
	clSync(t, a, b, calls)
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("3000 entries applied in %s", d)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if rrs, ok := b.Lookup("host2999.bulk.lan", dns.TypeA); ok && len(rrs) == 1 {
			break
		}
	}
	if rrs, ok := b.Lookup("host2999.bulk.lan", dns.TypeA); !ok || len(rrs) != 1 {
		t.Fatal("applied record not answered")
	}
	// Loeschen ueber den Cluster
	recs, _ := a.Records(ctx)
	for _, r := range recs[:100] {
		if err := a.DeleteRecord(ctx, r.ID); err != nil {
			t.Fatal(err)
		}
	}
	clSync(t, a, b, la.take())
	if got, _ := b.Records(ctx); len(got) != 2900 {
		t.Fatalf("b has %d records after deletes", len(got))
	}
}
