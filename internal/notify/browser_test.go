package notify

import (
	"context"
	"testing"
)

// Browser-Meldungen tragen mit, ob es eine Stoerung ist (wie isDownKind) - die Seite raet das nicht mehr aus dem
// Namen der Art (ipam64, monitor_problem und Co. waren sonst eine gruene Entwarnung, summary_up eine Stoerung).
func TestBrowserEventDown(t *testing.T) {
	ch, cancel := Browser.Subscribe()
	defer cancel()
	for kind, want := range map[Kind]bool{KindDown: true, KindIPAM: true, KindMonitorProblem: true, KindDynFail: true, KindSummary: true,
		KindUp: false, KindSummaryUp: false, KindMonitorOK: false, KindTest: false} {
		if err := (browserSender{}).Send(context.Background(), &Channel{Name: "b"}, Message{Kind: kind, URL: "https://n/x"}); err != nil {
			t.Fatal(err)
		}
		if ev := <-ch; ev.Down != want || ev.Kind != string(kind) || ev.URL != "https://n/x" {
			t.Errorf("%s: %+v", kind, ev)
		}
	}
}
