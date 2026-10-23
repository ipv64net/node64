package dyndns

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

// Benachrichtigungen des Moduls ueber die Standardkanaele des Kerns. Sie gehen immer lokal raus
// (der hub kennt DynDNS nicht) und werden in der Ruhezeit verworfen; der Verlauf zeigt alles.

const (
	SetNotifyIP    = "dyndns.notify_ip"    // oeffentliche Adresse gewechselt
	SetNotifyFail  = "dyndns.notify_fail"  // Update fehlgeschlagen bzw. Ziel pausiert
	SetNotifyLimit = "dyndns.notify_limit" // Update-Limit fast oder ganz erreicht
	// je Tag hoechstens eine Meldung "fast erreicht" und eine "erreicht"
	setLimitWarnSent    = "dyndns.limit_warn_notified"
	setLimitReachedSent = "dyndns.limit_reached_notified"
)

var notifyOnceMu sync.Mutex

func (m *Module) notifyOn(ctx context.Context, key string) bool {
	return m.core.SettingOr(ctx, key, "1") == "1"
}

// alert schickt eine Meldung, wenn sie eingeschaltet ist. text: Paare fuer einen uebersetzten Text ("text", Schluessel,
// danach Platzhalter und Werte); msg bleibt der Text fuer Verlauf und Schnittstellen.
func (m *Module) alert(ctx context.Context, key string, kind notify.Kind, name, reason, msg string, text ...string) {
	if m.notifier == nil || !m.notifyOn(ctx, key) {
		return
	}
	now := time.Now().UTC()
	var data map[string]string
	if len(text) > 1 {
		data = map[string]string{}
		for i := 0; i+1 < len(text); i += 2 {
			data[text[i]] = text[i+1]
		}
	}
	m.notifier(notify.Alert{EventID: "dyn-" + string(kind) + "-" + name + "-" + strconv.FormatInt(now.UnixNano(), 36), Kind: kind, Time: now,
		Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true}, Reason: reason, Message: msg, Data: data})
}

// notifyOnce: true, wenn heute unter diesem Schluessel noch nicht gemeldet wurde (und merkt es sich).
func (m *Module) notifyOnce(ctx context.Context, key string) bool {
	notifyOnceMu.Lock()
	defer notifyOnceMu.Unlock()
	today := time.Now().Format("2006-01-02")
	if m.core.SettingOr(ctx, key, "") == today {
		return false
	}
	_ = m.core.SetSetting(ctx, key, today)
	return true
}
