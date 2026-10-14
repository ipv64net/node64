package notify

import (
	"strings"
	"testing"
	"time"
)

// DNS64-Meldungen: wie DynDNS lokal, eigener Titel, Link auf /dns64.
func TestDNS64Alerts(t *testing.T) {
	d, st, rec := testDispatcher(t, nil)
	addChannel(t, st, "default", true)
	info := CheckInfo{Name: "Quad9 (DoT)", NotifyDown: true, NotifyUp: true, Local: true}
	d.Dispatch(Alert{EventID: "n1", Kind: KindDNS64Down, Check: info, Time: time.Now(), Reason: "i/o timeout", Message: "tls://dns.quad9.net"})
	d.Dispatch(Alert{EventID: "n2", Kind: KindDNS64Up, Check: info, Time: time.Now()})
	msgs := waitMsgs(t, rec, 2)
	if !strings.Contains(msgs[0].Title, "Quad9 (DoT)") || !strings.Contains(msgs[0].Text, "i/o timeout") || (msgs[0].URL != "" && !strings.HasSuffix(msgs[0].URL, "/dns64")) {
		t.Fatalf("down message: %+v", msgs[0])
	}
	if msgs[1].Priority != 2 || msgs[0].Priority != 4 {
		t.Fatalf("priorities: %d %d", msgs[0].Priority, msgs[1].Priority)
	}
}
