package notify

import (
	"strings"
	"testing"
	"time"
)

// Fruehwarnung von Honeypot64: Modul-Meldung, gilt als Stoerung (Prioritaet 4), Link auf /honeypot/watch.
func TestHoneypotWatchAlert(t *testing.T) {
	if !IsHoneypot(KindHoneypotWatch) || !IsModule(KindHoneypotWatch) || !isDownKind(KindHoneypotWatch) {
		t.Fatal("honeypot_watch must be a honeypot module warning")
	}
	d, st, rec := testDispatcher(t, nil)
	addChannel(t, st, "default", true)
	info := CheckInfo{Name: "Honeypot64", NotifyDown: true, NotifyUp: true, Local: true}
	d.Dispatch(Alert{EventID: "w1", Kind: KindHoneypotWatch, Check: info, Time: time.Now(), Message: "203.0.113.9 – Buero (203.0.113.0/24)"})
	msgs := waitMsgs(t, rec, 1)
	if msgs[0].Kind != KindHoneypotWatch || msgs[0].Priority != 4 || !strings.Contains(msgs[0].Text, "203.0.113.9") ||
		(msgs[0].URL != "" && !strings.HasSuffix(msgs[0].URL, "/honeypot/watch")) {
		t.Fatalf("message: %+v", msgs[0])
	}
}
