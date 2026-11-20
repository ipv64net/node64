package ipam64

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/ipam64/oui"
	"github.com/ipv64net/node64/internal/notify"
)

// Scan & Konflikte (Plan Stufe I5). Konflikte kommen aus der Zusammenfuehrung (merge.go: dup, mac, lease), Hinweise
// entstehen hier: unbekanntes Geraet im DHCP-Adressbereich (fest eingestellt, keine Lease, gerade gesehen), feste
// Adresse mit DNS lange nicht gesehen, fremder DHCP-Server (aus DNS64). Unbekannte Geraete sind Adressen, die nur die
// Nachbartabelle kennt.
// Ignorierte MACs (je Node) erscheinen dort nicht mehr. Benachrichtigungen: neuer Konflikt bzw. neues Geraet (je Art
// abschaltbar, neue Geraete erst eine Stunde nach dem Start des Moduls - sonst meldete der erste Scan alles - und nur
// gerade gesehene).

const (
	setIgnored        = "ipam64.ignored"         // ignorierte MACs (JSON-Liste)
	setNotifyConflict = "ipam64.notify_conflict" // "1" = neue Konflikte melden (Standard an)
	setNotifyNew      = "ipam64.notify_new"      // "1" = neue Geraete melden (Standard aus)

	staleAfter  = 7 * 24 * time.Hour // feste Adresse mit DNS so lange nicht gesehen: Hinweis
	newDevGrace = time.Hour          // nach dem Start: erst dann neue Geraete melden
	maxIgnored  = 1000
)

// vendorOf liefert den Hersteller einer MAC ("random" = zufaellige MAC, "" = unbekannt).
func vendorOf(mac string) string {
	if mac == "" {
		return ""
	}
	if oui.Random(mac) {
		return "random"
	}
	return oui.Lookup(mac)
}

// Finding ist ein Konflikt oder Hinweis.
type Finding struct {
	Kind     string   `json:"kind"`     // dup | mac | lease | double (Konflikte), pool | stale | foreign (Hinweise)
	Severity string   `json:"severity"` // conflict | hint
	IP       string   `json:"ip"`
	Prefix   string   `json:"prefix,omitempty"`
	Name     string   `json:"name,omitempty"`
	MACs     []string `json:"macs,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// Key ist die Kennung eines Fundes (fuer Benachrichtigungen).
func (f Finding) Key() string { return f.Kind + "|" + f.IP + "|" + strings.Join(f.MACs, ",") }

// ForeignDHCP ist ein fremder DHCP-Server, den DNS64 gesehen hat.
type ForeignDHCP struct{ Net, Server string }

// SetForeign liefert die fremden DHCP-Server aus DNS64 (cmd/node64/ipam.go).
func (m *Module) SetForeign(f func(ctx context.Context) []ForeignDHCP) { m.foreign = f }

// SetNotifier installiert den Versand (Dispatcher des Kerns).
func (m *Module) SetNotifier(f func(notify.Alert)) { m.notifier = f }

// Findings liefert Konflikte und Hinweise aller Praefixe.
func (m *Module) Findings(ctx context.Context) ([]Finding, error) {
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	now := m.now()
	var out []Finding
	for _, n := range snap.Nets {
		for _, e := range snap.Entries(n.Prefix) {
			name := e.Name
			switch {
			case e.Conflict != "":
				out = append(out, Finding{Kind: e.Conflict, Severity: "conflict", IP: e.IP, Prefix: n.CIDR, Name: name, MACs: e.MACs})
			case n.inPool(e.ip) && onlyScan(e) && e.State == "online": // nur gerade gesehen, nicht der gegangene Client nach Ablauf der Lease
				out = append(out, Finding{Kind: "pool", Severity: "hint", IP: e.IP, Prefix: n.CIDR, MACs: nonEmpty(e.MAC)})
			case e.UID != "" && e.Status == StatusActive && slices.Contains(e.Sources, SrcDNS) && n.Scan != ScanOff && n.Attached &&
				(e.Seen.IsZero() || now.Sub(e.Seen) > staleAfter):
				out = append(out, Finding{Kind: "stale", Severity: "hint", IP: e.IP, Prefix: n.CIDR, Name: name})
			}
		}
	}
	out = append(out, m.doubleFindings()...)
	if m.foreign != nil {
		for _, f := range m.foreign(ctx) {
			out = append(out, Finding{Kind: "foreign", Severity: "hint", IP: f.Server, Prefix: f.Net})
		}
	}
	return out, nil
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// onlyScan: die Adresse kennt nur die Nachbartabelle (kein IPAM64, keine Lease, kein DNS, kein anderes Modul).
func onlyScan(e Entry) bool { return len(e.Sources) == 1 && e.Sources[0] == SrcScan }

// Unknown liefert die unbekannten Geraete (nur Nachbartabelle, nicht ignoriert), neueste zuerst.
func (m *Module) Unknown(ctx context.Context) ([]Entry, error) {
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	ign := m.Ignored(ctx)
	var out []Entry
	for _, n := range snap.Nets {
		for _, e := range snap.Entries(n.Prefix) {
			if onlyScan(e) && e.Conflict == "" && !slices.Contains(ign, e.MAC) {
				out = append(out, e)
			}
		}
	}
	slices.SortFunc(out, func(a, b Entry) int { return b.First.Compare(a.First) })
	return out, nil
}

// Ignored liefert die ignorierten MACs dieser Node.
func (m *Module) Ignored(ctx context.Context) []string {
	var list []string
	_ = json.Unmarshal([]byte(m.core.SettingOr(ctx, setIgnored, "[]")), &list)
	return list
}

// SetIgnored nimmt eine MAC in die Liste auf bzw. heraus.
func (m *Module) SetIgnored(ctx context.Context, mac string, on bool) error {
	mac, err := normMAC(mac)
	if err != nil || mac == "" {
		return ErrMAC
	}
	list := m.Ignored(ctx)
	i := slices.Index(list, mac)
	switch {
	case on && i < 0:
		if len(list) >= maxIgnored {
			list = list[1:]
		}
		list = append(list, mac)
	case !on && i >= 0:
		list = slices.Delete(list, i, i+1)
	default:
		return nil
	}
	b, _ := json.Marshal(list)
	return m.core.SetSetting(ctx, setIgnored, string(b))
}

// NotifyFlags liefert die Schalter der Benachrichtigungen (Konflikte, neue Geraete).
func (m *Module) NotifyFlags(ctx context.Context) (conflicts, devices bool) {
	return m.core.SettingOr(ctx, setNotifyConflict, "1") == "1", m.core.SettingOr(ctx, setNotifyNew, "0") == "1"
}

// SetNotifyFlags stellt die Benachrichtigungen ein.
func (m *Module) SetNotifyFlags(ctx context.Context, conflicts, devices bool) error {
	if err := m.core.SetSetting(ctx, setNotifyConflict, boolText(conflicts)); err != nil {
		return err
	}
	return m.core.SetSetting(ctx, setNotifyNew, boolText(devices))
}

func boolText(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// notifyCheck meldet neue Konflikte und neue Geraete einmal (Hintergrundschleife). Geloeste Funde fallen aus dem
// Gedaechtnis, ein erneutes Auftreten wird wieder gemeldet.
func (m *Module) notifyCheck(ctx context.Context) {
	if m.notifier == nil {
		return
	}
	onConflict, onNew := m.NotifyFlags(ctx)
	found, err := m.Findings(ctx)
	if err != nil {
		return
	}
	m.recMu.Lock()
	defer m.recMu.Unlock()
	if m.notified == nil {
		m.notified = map[string]bool{}
	}
	cur := map[string]bool{}
	for _, f := range found {
		if f.Severity != "conflict" {
			continue
		}
		k := f.Key()
		cur[k] = true
		if !m.notified[k] && onConflict {
			m.send(f.IP, "ipam64_conflict_"+f.Kind, map[string]string{"ip": f.IP, "macs": strings.Join(f.MACs, ", "), "name": f.Name})
		}
	}
	if onNew && !m.started.IsZero() && m.now().Sub(m.started) >= newDevGrace {
		if list, err := m.Unknown(ctx); err == nil {
			for _, e := range list {
				k := "new|" + e.MAC
				cur[k] = true
				// nur gerade gesehene: ein gegangener DHCP-Client steht nach Ablauf seiner Lease hier, ist aber nicht neu
				if !m.notified[k] && e.State == "online" && !e.First.Before(m.started.Add(newDevGrace)) {
					v := e.Vendor
					if v == "random" {
						v = ""
					}
					m.send(e.IP, "ipam64_new_device", map[string]string{"ip": e.IP, "mac": e.MAC, "vendor": v})
				}
			}
		}
	}
	m.notified = cur
}

func (m *Module) send(name, text string, data map[string]string) {
	d := map[string]string{"text": "notify.text." + text}
	for k, v := range data {
		d[k] = v
	}
	now := m.now().UTC()
	m.log.Info("notification", "kind", notify.KindIPAM, "name", name, "text", text)
	m.notifier(notify.Alert{EventID: "ipam64-" + strconv.FormatInt(now.UnixNano(), 36), Kind: notify.KindIPAM, Time: now,
		Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true}, Data: d})
}

// ouiSize: Zahl der Eintraege der Herstellerliste (0 = keine eingebaut).
func ouiSize() int { return oui.Size() }
