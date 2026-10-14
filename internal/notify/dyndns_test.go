package notify

import (
	"strings"
	"testing"
	"time"
)

// DynDNS-Meldungen: immer ueber lokale Kanaele (auch wenn der hub sendet), eigener Titel und Link,
// in der Ruhezeit verworfen statt gesammelt (keine Sammelmeldung danach).
func TestDynDNSAlerts(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 1, 7, 12, 0, 0, 0, time.UTC)}
	d, st, rec := testDispatcher(t, map[string]string{SetQuietEnabled: "1", SetQuietFrom: "22:00", SetQuietTo: "07:00", SetQuietDays: "1,2,3,4,5,6,7", SetQuietTZ: "UTC"})
	d.now = clk.now
	d.SetServerSends(func() bool { return true }) // verknuepft und verbunden
	addChannel(t, st, "default", true)
	info := CheckInfo{Name: "IPv4", NotifyDown: true, NotifyUp: true, Local: true}
	d.Dispatch(Alert{EventID: "d1", Kind: KindDynIP, Check: info, Time: clk.now(), Message: "IPv4: 1.2.3.4 → 5.6.7.8"})
	msgs := waitMsgs(t, rec, 1)
	if !strings.Contains(msgs[0].Title, "IPv4") || !strings.Contains(msgs[0].Text, "5.6.7.8") || (msgs[0].URL != "" && !strings.HasSuffix(msgs[0].URL, "/dyndns")) {
		t.Fatalf("dyndns message: %+v", msgs[0])
	}
	// ein normaler Check-Alert geht in dem Zustand nicht lokal raus (der hub sendet)
	d.Dispatch(Alert{EventID: "h1", Kind: KindDown, Check: CheckInfo{Token: "t", Name: "Web", NotifyDown: true, NotifyUp: true}, Time: clk.now()})
	time.Sleep(200 * time.Millisecond)
	if n := len(rec.list()); n != 1 {
		t.Fatalf("check alert must stay with the hub, got %d messages", n)
	}
	// Ruhezeit: verwerfen, danach keine Sammelmeldung
	clk.set(time.Date(2026, 1, 7, 23, 30, 0, 0, time.UTC))
	d.SetServerSends(nil)
	d.Dispatch(Alert{EventID: "d2", Kind: KindDynFail, Check: info, Time: clk.now(), Reason: "badauth"})
	time.Sleep(200 * time.Millisecond)
	clk.set(time.Date(2026, 1, 8, 7, 1, 0, 0, time.UTC))
	time.Sleep(400 * time.Millisecond)
	if n := len(rec.list()); n != 1 {
		t.Fatalf("dyndns alert in quiet hours must be dropped, got %d messages: %+v", n, rec.list())
	}
}
