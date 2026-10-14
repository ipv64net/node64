package notify

import (
	"strings"
	"testing"
	"time"
)

// Tageskontingent erreicht (vom hub): eigene Meldung an die Standardkanaele, in der Ruhezeit verworfen.
func TestQuotaAlert(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 1, 7, 18, 15, 0, 0, time.UTC)}
	d, st, rec := testDispatcher(t, map[string]string{SetQuietEnabled: "1", SetQuietFrom: "22:00", SetQuietTo: "07:00", SetQuietDays: "1,2,3,4,5,6,7", SetQuietTZ: "UTC"})
	d.now = clk.now
	d.SetSendServerChannels(true) // wie auf dem hub
	addChannel(t, st, "default", true)
	d.Dispatch(Alert{EventID: "quota-522-20260107", Kind: KindQuota, Time: clk.now(), Message: "8192/8192", Check: CheckInfo{UserID: 1, Name: "Healthchecks", NotifyDown: true, NotifyUp: true}})
	msgs := waitMsgs(t, rec, 1)
	if !strings.Contains(msgs[0].Title, "Tageskontingent") || !strings.Contains(msgs[0].Text, "8192 von 8192") || !strings.Contains(msgs[0].Text, "Mitternacht") {
		t.Fatalf("quota message: %+v", msgs[0])
	}
	if c, _ := mailStatus(KindQuota, "de"); c != "#f59f00" {
		t.Fatalf("quota mail color = %s", c)
	}
	clk.set(time.Date(2026, 1, 7, 23, 30, 0, 0, time.UTC))
	d.Dispatch(Alert{EventID: "quota-522-20260108", Kind: KindQuota, Time: clk.now(), Message: "8192/8192", Check: CheckInfo{UserID: 1, Name: "Healthchecks", NotifyDown: true, NotifyUp: true}})
	time.Sleep(200 * time.Millisecond)
	clk.set(time.Date(2026, 1, 8, 7, 1, 0, 0, time.UTC))
	time.Sleep(400 * time.Millisecond)
	if n := len(rec.list()); n != 1 {
		t.Fatalf("quota alert in quiet hours must be dropped, got %d", n)
	}
}
