package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Meldungen von Monitor64 entstehen in der Sprache des Kanals: Dienstnamen, Zustandstexte und Ursachen kommen als
// uebersetzbare Texte (model.T, auch zusammengesetzt) und stehen in der Meldung in genau dieser Sprache.
func TestMonitorMessageLanguage(t *testing.T) {
	d, _, _ := testDispatcher(t, nil)
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	lines := []MonitorLine{
		{Kind: "problem", Key: "fs:/", Name: model.T("monitor64.svc.fs", "name", "/"), State: "crit", Since: now.Add(-10 * time.Minute),
			Detail: model.T("monitor64.detail.threshold", "metric", model.Sub(model.T("monitor64.kind.fs_used")), "value", model.Sub("92 %"), "limit", model.Sub("90 %"))},
		{Kind: "problem", Key: "zfs:tank", Name: "ZFS tank", State: "warn",
			Detail: "DEGRADED · " + model.T("monitor64.txt.free", "v", "3,0 TB") + " · " + model.T("monitor64.txt.readonly")},
		{Kind: "problem", Key: "access:a1", Name: model.T("monitor64.detail.access", "name", model.Sub(model.T("monitor64.access.docker"))), State: "warn",
			Detail: model.T("monitor64.txt.partial", "n", 1) + ": inspect (2): connection refused"},
		{Kind: "problem", Key: "vm:100", Name: model.Raw("i18n:monitor64.state.ok (VM 100)"), State: "crit",
			Detail: model.T("monitor64.txt.stopped") + ", " + model.T("monitor64.txt.should_run_onboot")},
		{Kind: "problem", Key: "mem", Name: "Arbeitsspeicher", State: "warn", Detail: "alter gespeicherter Text"}, // vor der Umstellung gespeichert
	}
	raw, _ := json.Marshal(lines)
	a := Alert{EventID: "m1", Kind: KindMonitorProblem, Time: now, Check: CheckInfo{Token: "m64:h1", Name: "nas01", Type: "monitor64", Local: true},
		Data: map[string]string{"host": "nas01", "path": "/monitor64/host/h1", "severity": "crit", "lines": string(raw)}}

	en := d.compose("en", a)
	for _, want := range []string{"Filesystem /: Critical – File system / drive used 92 % (threshold 90 %)", "ZFS tank: Warning – DEGRADED · 3,0 TB free · read-only",
		"Access Docker API: Warning – 1 sub-query(ies) failed: inspect (2): connection refused", "i18n: monitor64.state.ok (VM 100): Critical – stopped, should be running (start at boot)",
		"Arbeitsspeicher: Warning – alter gespeicherter Text"} {
		if !strings.Contains(en.Text, want) {
			t.Errorf("en: %q fehlt in\n%s", want, en.Text)
		}
	}
	// kein deutscher Dienstname bzw. Zustandstext in der englischen Meldung, kein rohes Token
	for _, bad := range []string{"Dateisystem", "Zugang", "frei", "nur lesbar", "Schwelle", "gestoppt", "soll laufen", "Teilabfrage", "i18n:m", "monitor64.txt.", "monitor64.svc."} {
		if strings.Contains(en.Text, bad) || strings.Contains(en.Title, bad) {
			t.Errorf("en: %q in der Meldung:\n%s\n%s", bad, en.Title, en.Text)
		}
	}
	de := d.compose("de", a)
	for _, want := range []string{"Dateisystem /: Kritisch – Dateisystem / Laufwerk belegt 92 % (Schwelle 90 %)", "ZFS tank: Warnung – DEGRADED · 3,0 TB frei · nur lesbar",
		"Zugang Docker-API: Warnung – 1 Teilabfrage(n) fehlgeschlagen: inspect (2): connection refused", "(VM 100): Kritisch – gestoppt, soll laufen (beim Booten starten)"} {
		if !strings.Contains(de.Text, want) {
			t.Errorf("de: %q fehlt in\n%s", want, de.Text)
		}
	}
	// Betreff bei einer Zeile: der uebersetzte Dienstname
	one, _ := json.Marshal(lines[:1])
	a.Data["lines"] = string(one)
	if m := d.compose("en", a); !strings.Contains(m.Title, "nas01: Filesystem /") {
		t.Errorf("en Betreff = %q", m.Title)
	}
	if m := d.compose("de", a); !strings.Contains(m.Title, "nas01: Dateisystem /") {
		t.Errorf("de Betreff = %q", m.Title)
	}
	// Sammelmeldung nach der Ruhezeit
	if s := d.monitorSummary("en", a); !strings.Contains(s, "Filesystem /: File system / drive used 92 % (threshold 90 %)") {
		t.Errorf("en Sammelzeile = %q", s)
	}
	// Zeitpunkte in Texten des Kerns werden formatiert, unbekannte Schluessel zeigen Schluessel und Werte
	if s := d.tx("de", model.T("monitor64.detail.vanished", "since", "2026-11-09T10:00:00Z")); strings.Contains(s, "T10:00:00Z") || !strings.Contains(s, "2026") {
		t.Errorf("Zeitpunkt = %q", s)
	}
	if s := d.tx("en", model.T("monitor64.txt.gibt_es_nicht", "v", "x")); s != "txt.gibt_es_nicht (x)" {
		t.Errorf("unbekannter Schluessel = %q", s)
	}
}
