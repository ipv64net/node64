// Package apis enthaelt die API-Sammler von Monitor64 fuer Proxmox VE, Proxmox Backup Server und Docker (Plan
// docs/PLAN-NODE64-MONITOR64.md, "Zugaenge – APIs"). Jeder Sammler liefert Dienste im gemeinsamen Format
// (internal/monitor64/model) und nutzt die vorhandenen Clients aus internal/proxmox (Cluster-Adressen,
// Zertifikats-Pinning, Docker lokal/entfernt) – nur lesende Abfragen.
//
// Je Art ein Sammler mit Collect (eine Abfragerunde, nicht gleichzeitig aufrufen) und Test (Assistent "Verbindung
// testen"). Zaehler (Netz, Disk-I/O) werden im Sammler zwischen zwei Runden in Raten umgerechnet. Schlaegt nur ein
// Teil der Abfragen fehl, liefert Collect die uebrigen Dienste und einen *PartialError (der Kern macht daraus die
// Warnung "Zugang API"); ohne Dienste ist der Fehler ein normaler Fehler (Zugang antwortet nicht).
//
// Texte (Service.Name, Service.Text, Facts, eigene Fehlertexte) sind uebersetzbar (model.T); Eigennamen und
// Fehlertexte vom Geraet bzw. aus fremden Clients stehen als Parameter im Token oder laufen durch model.Raw.
// Geheimnisse (Token-Secret, Schluessel) stehen nie in Fehlertexten; freie Fehlertexte sind deshalb feste Teile und
// nie Parameter (scrub findet sie sonst nicht).
package apis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Standardwerte der Sammler.
const (
	DefaultTimeout      = 30 * time.Second    // ganze Abfragerunde (Plan: hoechstens 80 % des Intervalls, max. 30 s)
	DefaultSmartEvery   = 30 * time.Minute    // SMART (Platten nicht unnoetig wecken)
	DefaultUpdatesEvery = 60 * time.Minute    // ausstehende Updates
	DefaultBackupMaxAge = 26 * time.Hour      // PBS: Backup einer Gruppe aelter -> backup_old
	configEvery         = 10 * time.Minute    // Gast-Config (onboot) bzw. Neustart-Richtlinie neu lesen
	slowEvery           = 10 * time.Minute    // PBS: Gruppen je Datastore
	optionalRetry       = 60 * time.Minute    // fehlende Funktion (z. B. kein Ceph) so lange nicht neu fragen
	parallel            = 4                   // gleichzeitige Einzelabfragen (Gast-Config, SMART, inspect)
	maxPartErrors       = 5                   // so viele Teilfehler im Text
	staleAfter          = 30 * 24 * time.Hour // PBS: Gruppe ohne Backup so lange -> beim Erkennen nicht vorgewaehlt
	lockGrace           = 4 * time.Hour       // gestoppter Gast mit Sperre so lange absichtlich aus (wie pveLockGrace in internal/proxmox)
)

// TestResult ist das Ergebnis von "Verbindung testen" im Assistenten.
type TestResult struct {
	OK          bool          `json:"ok"`
	Error       string        `json:"error,omitempty"`
	Version     string        `json:"version,omitempty"`
	Node        string        `json:"node,omitempty"`    // Proxmox VE: Node dieses Hosts (eingestellt bzw. erkannt)
	Cluster     string        `json:"cluster,omitempty"` // Proxmox VE: Clustername (leer = Einzel-Node)
	Nodes       []ClusterNode `json:"nodes,omitempty"`   // Proxmox VE: alle Nodes (Vorschlag "als eigene Hosts anlegen")
	Summary     string        `json:"summary,omitempty"` // kurz, z. B. "12 Gaeste" bzw. "8 Container, 7 laufen"
	Warning     string        `json:"warning,omitempty"` // erreichbar, aber eingeschraenkt (Rechte)
	Fingerprint string        `json:"fingerprint,omitempty"`
	CertSubject string        `json:"cert_subject,omitempty"`
	Trusted     bool          `json:"trusted"`
	// NeedConfirm: Zertifikat bzw. Host-Key nicht bestaetigt und kein Pin – Token bzw. Schluessel wurden nicht
	// gesendet. Nach der Bestaetigung mit Fingerprint als Pin erneut testen.
	NeedConfirm bool `json:"need_confirm,omitempty"`
	// CertChanged: das Geraet zeigt ein anderes Zertifikat als das gemerkte (z. B. FRITZ!Box nach neuem Namen) –
	// Zugangsdaten wurden nicht gesendet. Fingerprint ist der neue; die Oberflaeche bietet die Uebernahme an.
	CertChanged bool `json:"cert_changed,omitempty"`
}

// PartialError: einzelne Teilabfragen sind fehlgeschlagen, die uebrigen Dienste wurden geliefert.
//
// Prefixes nennt die Dienst-Schluessel, die wegen der Teilfehler in dieser Runde fehlen koennen (Vergleich mit
// strings.HasPrefix: "vm:" fuer alle VMs, "backup:store/" fuer die Backups eines Datastores, "updates" fuer genau den
// Dienst updates). Der Kern haelt fehlende Dienste mit diesen Praefixen auf dem vorigen Stand, statt sie
// "verschwunden" zu nennen. Fehlt ein Dienst ausserhalb der Praefixe, ist er wirklich weg.
type PartialError struct {
	Errs     []string // je Teilabfrage "was: Fehler"
	Prefixes []string // betroffene Schluessel-Praefixe (sortiert, ohne Doppelte)
}

// Affects sagt, ob ein fehlender Dienst mit diesem Schluessel vom Teilfehler betroffen sein kann.
func (e *PartialError) Affects(key string) bool {
	for _, p := range e.Prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

func (e *PartialError) Error() string {
	l := e.Errs
	more := ""
	if len(l) > maxPartErrors {
		more = fmt.Sprintf(" (+%d)", len(l)-maxPartErrors)
		l = l[:maxPartErrors]
	}
	return model.T("monitor64.txt.partial", "n", len(e.Errs)) + ": " + strings.Join(l, "; ") + more
}

// IsPartial sagt, ob err nur ein Teilfehler ist (Dienste sind trotzdem gueltig).
func IsPartial(err error) bool {
	var p *PartialError
	return errors.As(err, &p)
}

// partial sammelt Teilfehler einer Runde (sicher fuer gleichzeitige Einzelabfragen).
type partial struct {
	mu       sync.Mutex
	errs     []string
	prefixes map[string]bool
	secrets  []string
	foreign  bool // Fehler stammen aus fremden Clients (internal/proxmox): Text entschaerfen (model.Raw)
}

// add merkt einen Teilfehler; prefixes sind die Schluessel-Praefixe der Dienste, die dadurch fehlen koennen.
func (p *partial) add(what string, err error, prefixes ...string) {
	if err == nil {
		return
	}
	text := err.Error()
	if p.foreign {
		text = model.Raw(text)
	}
	msg := scrub(what+": "+text, p.secrets...)
	p.mu.Lock()
	p.errs = append(p.errs, msg)
	for _, pre := range prefixes {
		if p.prefixes == nil {
			p.prefixes = map[string]bool{}
		}
		p.prefixes[pre] = true
	}
	p.mu.Unlock()
}

// result: Dienste mit Teilfehler (nil, wenn alles gelang).
func (p *partial) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.errs) == 0 {
		return nil
	}
	pre := make([]string, 0, len(p.prefixes))
	for k := range p.prefixes {
		pre = append(pre, k)
	}
	sort.Strings(pre)
	return &PartialError{Errs: append([]string(nil), p.errs...), Prefixes: pre}
}

// scrub entfernt Geheimnisse aus einem Text (zusaetzliche Sicherung; die Clients schreiben sie ohnehin nicht).
func scrub(s string, secrets ...string) string {
	for _, sec := range secrets {
		if len(sec) >= 4 {
			s = strings.ReplaceAll(s, sec, "***")
			if q := url.QueryEscape(sec); q != sec { // als Parameter eines Tokens kodiert
				s = strings.ReplaceAll(s, q, "***")
			}
		}
	}
	return s
}

// foreignErr: Fehler eines fremden Clients (internal/proxmox) ohne Geheimnisse und entschaerft (nil bleibt nil).
func foreignErr(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(model.Raw(scrub(err.Error(), secrets...)))
}

// scrubErr: Fehler ohne Geheimnisse (nil bleibt nil).
func scrubErr(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(scrub(err.Error(), secrets...))
}

// absent: die Abfrage gibt es auf diesem System nicht (aeltere Version, Funktion nicht eingerichtet) – kein Fehler.
func absent(err error) bool {
	var pe *proxmox.Error
	if !errors.As(err, &pe) {
		return false
	}
	switch pe.Status {
	case 400, 404, 501:
		return true
	}
	return false
}

// num nimmt Zahlen auch als String (mit Leerzeichen) oder null an (Proxmox ist da nicht einheitlich).
type num float64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	s = strings.TrimSpace(s)
	if s == "" || s == "null" || s == "N/A" {
		*n = 0
		return nil
	}
	if s == "true" {
		*n = 1
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || !finite(f) { // ParseFloat nimmt auch "NaN"/"Inf"
		*n = 0 // unbekannter Wert: lieber 0 als die ganze Abfrage verwerfen
		return nil
	}
	*n = num(f)
	return nil
}

// optNum ist eine Zahl, die fehlen darf ("N/A", null, fehlt -> Set false).
type optNum struct {
	V   float64
	Set bool
}

func (n *optNum) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(b)), `"`))
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || !finite(f) {
		*n = optNum{}
		return nil
	}
	*n = optNum{V: f, Set: true}
	return nil
}

// rawText liest einen JSON-Wert als Text (String oder Zahl).
func rawText(b json.RawMessage) string {
	var s string
	if json.Unmarshal(b, &s) == nil {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(string(b))
}

// leadingUint liest die fuehrende Ganzzahl ("35 (Min/Max 20/45)" -> 35).
func leadingUint(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(s[:i], 10, 64)
	return v, err == nil
}

// counter merkt sich einen Zaehlerstand fuer Raten.
type counter struct {
	t time.Time
	v map[string]float64
}

// rate: Differenz je Sekunde; false bei erster Runde, Ruecksprung (Neustart, Ueberlauf) oder fehlender Zeit.
func rate(prev *counter, now time.Time, name string, cur float64) (float64, bool) {
	if prev == nil {
		return 0, false
	}
	old, ok := prev.v[name]
	dt := now.Sub(prev.t).Seconds()
	if !ok || dt <= 0 || cur < old {
		return 0, false
	}
	return (cur - old) / dt, true
}

// runParallel fuehrt f fuer jedes Element mit hoechstens parallel gleichzeitigen Aufrufen aus.
func runParallel[T any](ctx context.Context, items []T, f func(ctx context.Context, it T)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			f(ctx, it)
		}(it)
	}
	wg.Wait()
}

// kindOrder: Reihenfolge der Dienste in der Ausgabe.
func kindOrder(k string) int {
	order := []string{"cpu", "load", "mem", "swap", "fs", "updates", "cluster", "ha", "ceph", "store", "ds", "zfs", "disk",
		"job", "backup", "vm", "ct", "ctr"}
	for i, o := range order {
		if o == k {
			return i
		}
	}
	return len(order)
}

func sortServices(out []model.Service) {
	sort.SliceStable(out, func(i, j int) bool { return kindOrder(out[i].Kind) < kindOrder(out[j].Kind) })
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func pct(part, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return round2(part / total * 100)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func limitList(l []string, n int) []string {
	if len(l) <= n {
		return l
	}
	return append(append([]string{}, l[:n]...), fmt.Sprintf("+%d", len(l)-n))
}

// bytesText formatiert Bytes (1000er-Einheiten wie bei Plattengroessen, wie im Mapper).
func bytesText(v float64) string {
	if v < 0 {
		v = 0
	}
	f := v
	for _, u := range []string{"B", "KB", "MB", "GB", "TB", "PB"} {
		if f < 1000 || u == "PB" {
			if u == "B" {
				return fmt.Sprintf("%.0f B", f)
			}
			return strings.Replace(fmt.Sprintf("%.1f %s", f, u), ".", ",", 1)
		}
		f /= 1000
	}
	return ""
}

func mbitText(v float64) string {
	if v >= 1000 {
		return strings.Replace(fmt.Sprintf("%.1f Gbit/s", v/1000), ".", ",", 1)
	}
	if v >= 10 {
		return fmt.Sprintf("%.0f Mbit/s", v)
	}
	return strings.Replace(fmt.Sprintf("%.1f Mbit/s", v), ".", ",", 1)
}

// agoText: "vor 5 Min.", "vor 3 Std.", "vor 4 Tagen" (uebersetzbar).
func agoText(d time.Duration) string {
	switch {
	case d < time.Minute:
		return model.T("monitor64.txt.ago_now")
	case d < time.Hour:
		return model.T("monitor64.txt.ago_min", "n", int(d/time.Minute))
	case d < 48*time.Hour:
		return model.T("monitor64.txt.ago_h", "n", int(d/time.Hour))
	}
	return model.T("monitor64.txt.ago_days", "n", int(d/(24*time.Hour)))
}

// hoursText: Dauer in Stunden bzw. Tagen ("26 Std.", "3 Tage"; uebersetzbar, als Parameter mit model.Sub).
func hoursText(d time.Duration) string {
	if d < 48*time.Hour {
		return model.T("monitor64.txt.dur_h", "n", int(d/time.Hour))
	}
	return model.T("monitor64.txt.dur_days", "n", int(d/(24*time.Hour)))
}

// stateText: Zustand eines Gasts bzw. einer Aufgabe als Text; keys ordnet bekannte Zustaende ihrem Text zu,
// unbekannte bleiben roh (leer = "unbekannt").
func stateText(keys map[string]string, state string) string {
	if k, ok := keys[state]; ok {
		return model.T(k)
	}
	if s := shortText(state); s != "" {
		return model.Raw(s)
	}
	return model.T("monitor64.txt.unknown")
}

// Queries nennt die API-Pfade eines Sammlers im Klartext ("Was wird abgefragt?" im Host).
func (p *PVE) Queries() []string {
	n := "/nodes/" + firstNonEmpty(p.cfg.Node, "{node}")
	return []string{"GET /cluster/status", "GET " + n + "/status", "GET " + n + "/storage", "GET " + n + "/disks/zfs",
		"GET " + n + "/qemu?full=1", "GET " + n + "/lxc", "GET " + n + "/{qemu|lxc}/{vmid}/config (alle 10 min)",
		"GET /cluster/ha/status/current", "GET /cluster/ceph/status (falls eingerichtet)",
		"GET " + n + "/disks/list, " + n + "/disks/smart?disk=… (alle 30 min)", "GET " + n + "/apt/update (alle 60 min)"}
}

// Queries nennt die API-Pfade (PBS).
func (p *PBS) Queries() []string {
	return []string{"GET /nodes/localhost/status", "GET /status/datastore-usage",
		"GET /admin/verify, /admin/prune, /admin/sync, /admin/gc", "GET /admin/datastore/{store}/namespace, /groups (alle 10 min)",
		"GET /nodes/localhost/disks/list, /disks/smart?disk=… (alle 30 min)", "GET /nodes/localhost/apt/update (alle 60 min)"}
}

// Queries nennt die API-Pfade (Docker).
func (d *Docker) Queries() []string {
	return []string{"GET /containers/json?all=1", "GET /containers/{id}/stats?stream=false&one-shot=true (laufende)",
		"GET /containers/{id}/json (Neustarts, Health, Neustart-Richtlinie)", "GET /info (alle 10 min)"}
}
