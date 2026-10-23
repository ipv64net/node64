package notify

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Jede Art in beiden Sprachen: Betreff und Text vollstaendig uebersetzt (keine Schluessel, keine Platzhalter), in der
// Sprache des Kanals (keine deutschen Woerter im Englischen und umgekehrt), Gruende als Text statt Code.
func TestNotifyLanguages(t *testing.T) {
	d, _, _ := testDispatcher(t, map[string]string{SetBaseURL: "https://node.example", SetNodeName: "box"})
	info := CheckInfo{Name: "Shop", Type: "http", Target: "https://example.com", Token: "tok"}
	at := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	alerts := []Alert{
		{Kind: KindDown, Reason: "timeout"}, {Kind: KindUp, Duration: 90 * time.Second}, {Kind: KindFlappingStart, Reason: "status_mismatch", Flaps: 3},
		{Kind: KindFlappingEnd}, {Kind: KindDegraded, Reason: "connect_failed"}, {Kind: KindDegradedEnd}, {Kind: KindUnchecked}, {Kind: KindRechecked},
		{Kind: KindReminder, Reason: "timeout", Duration: time.Hour}, {Kind: KindTest},
		{Kind: KindDynIP, Message: "IPv4: 192.0.2.1 → 192.0.2.2"},
		{Kind: KindDynFail, Reason: "x509: certificate signed by unknown authority", Data: map[string]string{"text": "notify.text.dyndns_addr_failed", "family": "IPv4", "count": "3"}},
		{Kind: KindDynLimit, Data: map[string]string{"text": "notify.text.dyndns_limit_reached"}}, {Kind: KindDynOK},
		{Kind: KindDNS64Down, Reason: "i/o timeout"}, {Kind: KindDNS64Up}, {Kind: KindDNS64Lists}, {Kind: KindDNS64Cert},
		{Kind: KindCertFail}, {Kind: KindCertExpiry, Message: "2026-11-01 10:00 UTC"}, {Kind: KindCertOK},
		{Kind: KindCDNOnlineDown}, {Kind: KindCDNOnlineUp}, {Kind: KindCDNOnlineBlocked, Reason: "traffic"},
		{Kind: KindClusterDown, Data: map[string]string{"text": "notify.text.cluster_suspended", "reason": "maintenance"}}, {Kind: KindClusterUp},
		{Kind: KindHoneypotNew, Message: "2 IPs: 203.0.113.1, 203.0.113.2"}, {Kind: KindHoneypotWatch}, {Kind: KindHoneypotLogin},
		{Kind: KindProxmoxDown, Data: map[string]string{"what": "stopped", "type": "qemu", "name": "app", "system": "lab"}},
		{Kind: KindProxmoxUp, Data: map[string]string{"what": "stopped", "type": "qemu", "name": "app"}, Duration: time.Minute},
		{Kind: KindProxmoxThreshold, Data: map[string]string{"what": "cpu", "type": "lxc", "name": "db", "value": "95", "limit": "90"}},
		{Kind: KindProxmoxThresholdOK, Data: map[string]string{"what": "mem", "type": "lxc", "name": "db", "value": "50", "limit": "90"}},
		{Kind: KindProxmoxRestarted, Data: map[string]string{"type": "node", "name": "pve1"}},
		{Kind: KindProxmoxDown, Data: map[string]string{"what": "docker_unreachable", "name": "10.10.0.7", "source": "docker"}},
		{Kind: KindProxmoxDown, Data: map[string]string{"what": "unhealthy", "type": "docker", "name": "web", "source": "docker"}},
		{Kind: KindQuota, Message: "100/100"},
	}
	leftover := regexp.MustCompile(`\b(notify|pve|hc|docker|lang)\.[a-z_]+\.|\{[a-z_]+\}`)
	german := regexp.MustCompile(`[äöüÄÖÜß]|\b(ist|nicht|wieder|Grund|Zeitpunkt|gestört)\b`)
	english := regexp.MustCompile(`\b(Reason|Time|is|again|down|failed|reached|address|times|row|suspended|daily)\b`)
	for _, a := range alerts {
		a.Check, a.Time = info, at
		if a.Kind == KindProxmoxDown && a.Data["source"] == "docker" {
			a.Check.Name = a.Data["name"]
		}
		for _, lang := range []string{"de", "en"} {
			m := d.compose(lang, a)
			all := m.Title + "\n" + m.Text
			if leftover.MatchString(all) {
				t.Errorf("%s [%s]: unuebersetzt: %q", a.Kind, lang, leftover.FindString(all))
			}
			if lang == "en" && german.MatchString(all) {
				t.Errorf("%s [en]: deutsch: %q in %q", a.Kind, german.FindString(all), all)
			}
			if lang == "de" && english.MatchString(all) {
				t.Errorf("%s [de]: englisch: %q in %q", a.Kind, english.FindString(all), all)
			}
		}
	}
	// Gruende als Text
	if m := d.compose("de", Alert{Kind: KindDown, Check: info, Time: at, Reason: "timeout"}); !strings.Contains(m.Text, "Zeitüberschreitung") {
		t.Fatalf("grund de: %s", m.Text)
	}
	if m := d.compose("en", Alert{Kind: KindCDNOnlineBlocked, Check: info, Time: at, Reason: "traffic"}); !strings.Contains(m.Text, "traffic quota") {
		t.Fatalf("grund en: %s", m.Text)
	}
	if m := d.compose("de", Alert{Kind: KindDynFail, Check: info, Time: at, Data: map[string]string{"text": "notify.text.dyndns_addr_failed", "family": "IPv6", "count": "4"}}); !strings.Contains(m.Text, "IPv6-Adresse 4-mal") {
		t.Fatalf("dyndns de: %s", m.Text)
	}
}

// Die Sprache haengt am Kanal: derselbe Anlass geht an einen deutschen und einen englischen Kanal je in seiner Sprache.
func TestNotifyChannelLanguage(t *testing.T) {
	d, st, rec := testDispatcher(t, map[string]string{SetBaseURL: "https://node.example"})
	addChannel(t, st, "de", true)
	en := addChannel(t, st, "en", true)
	en.Lang = "en"
	if err := st.Update(context.Background(), en); err != nil {
		t.Fatal(err)
	}
	d.Dispatch(Alert{EventID: "l1", Kind: KindDown, Check: CheckInfo{Name: "Shop", Type: "http", NotifyDown: true, NotifyUp: true, Local: true}, Time: time.Now(), Reason: "timeout"})
	msgs := waitMsgs(t, rec, 2)
	got := map[string]string{}
	for _, m := range msgs {
		got[m.Language] = m.Title + " " + m.Text
	}
	if !strings.Contains(got["de"], "gestört") || !strings.Contains(got["de"], "Zeitüberschreitung") || !strings.Contains(got["en"], "is down") || strings.Contains(got["en"], "gestört") {
		t.Fatalf("sprachen: %+v", got)
	}
}

// Statusbalken der Mail passt zum Betreff: Stoerungen rot, Entwarnungen gruen, Warnungen orange (auch Modul-Meldungen).
func TestMailStatusMatchesKind(t *testing.T) {
	red, green, orange := "#d63939", "#2fb344", "#f59f00"
	for k, want := range map[Kind]string{KindDown: red, KindReminder: red, KindProxmoxDown: red, KindDynFail: red, KindDNS64Down: red,
		KindCertFail: red, KindCDNOnlineDown: red, KindCDNOnlineBlocked: red, KindClusterDown: red, KindHoneypotWatch: red,
		KindUp: green, KindProxmoxUp: green, KindProxmoxThresholdOK: green, KindDynOK: green, KindDNS64Up: green, KindCertOK: green,
		KindCDNOnlineUp: green, KindClusterUp: green, KindRechecked: green,
		KindDegraded: orange, KindFlappingStart: orange, KindProxmoxThreshold: orange, KindCertExpiry: orange, KindQuota: orange} {
		for _, lang := range []string{"de", "en"} {
			if c, label := mailStatus(k, lang); c != want || label == "" {
				t.Errorf("%s [%s]: %s %q, want %s", k, lang, c, label, want)
			}
		}
	}
	if _, l := mailStatus(KindProxmoxThreshold, "en"); l != "Warning" {
		t.Fatalf("label en: %q", l)
	}
}
