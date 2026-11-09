// Package promscrape ist der Zugang "Prometheus abfragen" von Monitor64 (Plan docs/PLAN-NODE64-MONITOR64.md,
// "Prometheus abfragen (Phase 3)"): ein Exporter wird per HTTP(S) im Textformat abgefragt (eigener kleiner Parser,
// keine Bibliothek).
//
// node_exporter und windows_exporter werden auf einen Agent-Bericht (m64proto.Report) abgebildet; den wertet der
// Mapper des Kerns aus (Config.Map = monitor64.MapReport), damit es dieselben Dienste, Schluessel, Messgroessen und
// Facts gibt wie beim Monitor64-Agent. Zaehler bleiben roh, Raten rechnet der Mapper aus zwei Berichten (der
// Sammler haelt den vorigen). Fuer beliebige Exporter gibt es eigene Metriken (CustomMetric).
//
// Wie bei den API-Sammlern: Collect (eine Runde, nicht gleichzeitig aufrufen) und Test (Assistent). Faellt ein
// Sammler im Exporter aus (node_scrape_collector_success bzw. windows_exporter_collector_success = 0), liefert Collect
// die uebrigen Dienste und einen *apis.PartialError mit den betroffenen Schluessel-Praefixen. Geheimnisse (Passwort,
// Token) stehen nie in Fehlertexten.
package promscrape

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Standardwerte.
const (
	DefaultTimeout = 20 * time.Second
	DefaultPort    = 9100 // node_exporter (windows_exporter: 9182)
)

// Erkannte Exporter.
const (
	ExporterNode    = "node_exporter"
	ExporterWindows = "windows_exporter"
	ExporterOther   = "" // unbekannt: nur eigene Metriken
)

// MapFunc bildet einen Bericht auf Dienste ab (monitor64.MapReport); prev ist der vorige Bericht (nil = erster).
type MapFunc func(prev, cur *m64proto.Report) []model.Service

// Config sind die Verbindungsdaten eines Exporters.
type Config struct {
	URL     string         // http(s)://host:9100/metrics; ohne Schema/Port/Pfad: http://, DefaultPort, /metrics
	User    string         // Basic-Auth-Benutzer (Secret = Passwort); leer und Secret gesetzt = Bearer-Token
	Secret  string         // Passwort bzw. Token (nie ausgeben)
	Pin     string         // SHA-256 des Zertifikats (hex, https); leer = System-CA
	Timeout time.Duration  // ganze Abfrage (0 = DefaultTimeout)
	Metrics []CustomMetric // eigene Metriken (beliebige Exporter)
	Map     MapFunc        // Mapper des Kerns (Pflicht fuer node_exporter/windows_exporter)
	Limits  Limits         // Grenzen des Parsers (leer = DefaultLimits)
	roots   *x509.CertPool // Tests: eigene Wurzeln statt System-CA
}

// Collector ist der Sammler eines Exporters.
type Collector struct {
	cfg Config
	f   *fetcher
	now func() time.Time

	mu       sync.Mutex
	prev     *m64proto.Report
	rates    map[string]rateState
	winIO    winIO
	known    map[string]bool // Schluessel der zuletzt gelieferten Dienste (fuer Teilfehler)
	exporter string
	version  string
}

// New baut den Sammler (prueft Adresse, Pin und eigene Metriken; fragt noch nichts ab).
func New(cfg Config) (*Collector, error) {
	u, err := NormalizeURL(cfg.URL, DefaultPort)
	if err != nil {
		return nil, err
	}
	cfg.URL = u
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	cfg.Limits = cfg.Limits.withDefaults()
	if err := ValidateCustom(cfg.Metrics); err != nil {
		return nil, err
	}
	if strings.ContainsAny(cfg.User, ":\r\n") || len(cfg.User) > 200 || strings.ContainsAny(cfg.Secret, "\r\n") {
		return nil, errors.New("Benutzer bzw. Passwort/Token enthält unzulässige Zeichen")
	}
	f, err := newFetcher(cfg.URL, cfg.User, cfg.Secret, cfg.Pin, cfg.Timeout, cfg.Limits.MaxBytes, cfg.roots)
	if err != nil {
		return nil, err
	}
	return &Collector{cfg: cfg, f: f, now: time.Now, rates: map[string]rateState{}, winIO: winIO{}, known: map[string]bool{}}, nil
}

// Close gibt Leerlauf-Verbindungen frei.
func (c *Collector) Close() { c.f.close() }

// Exporter liefert den zuletzt erkannten Exporter und seine Version.
func (c *Collector) Exporter() (kind, version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exporter, c.version
}

// scrape holt und liest die Metriken.
func (c *Collector) scrape(ctx context.Context) (*Metrics, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	body, err := c.f.fetch(ctx)
	if err != nil {
		return nil, c.scrub(err)
	}
	m, err := Parse(body, c.cfg.Limits)
	if err != nil {
		return nil, err
	}
	if m.Series == 0 {
		return nil, ErrNoMetrics
	}
	return m, nil
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (c *Collector) Collect(ctx context.Context) ([]model.Service, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, err := c.scrape(ctx)
	if err != nil {
		return nil, err
	}
	now := c.now()
	kind, ver := detect(m)
	c.exporter, c.version = kind, ver
	rep := buildReport(m, kind, now, c.winIO)
	var out []model.Service
	if rep != nil {
		if c.cfg.Map == nil {
			return nil, errors.New("monitor64: promscrape ohne Mapper")
		}
		out = c.cfg.Map(c.prev, rep)
		c.prev = rep
	}
	custom, rates := customServices(m, c.cfg.Metrics, now, c.rates)
	c.rates = rates
	out = append(out, custom...)
	perr := c.partial(m, kind, out)
	return out, perr
}

// partial: ausgefallene Sammler des Exporters als Teilfehler. Die Praefixe eines ausgefallenen Sammlers gehoeren immer
// dazu (auch direkt nach einem Neustart, wenn der Sammler noch keine Dienste kennt; sonst hiessen dessen Dienste
// "verschwunden"). Ausnahme sind die Sammler, die ohne die Funktion immer als fehlgeschlagen gelten (bond, mdadm,
// zfs ..., noDataCollector): sie zaehlen als Teilfehler nur, wenn es vorher Dienste unter ihren Praefixen gab (die
// Schluessel bleiben dann gemerkt, bis der Sammler wieder liefert); liegt ohnehin ein Teilfehler vor, werden ihre
// Praefixe mit gemeldet.
func (c *Collector) partial(m *Metrics, kind string, out []model.Service) error {
	failed := failedCollectors(m, kind)
	next := map[string]bool{}
	for _, s := range out {
		next[s.Key] = true
	}
	var errs []string
	var quiet []string // Praefixe der noDataCollector ohne gemerkte Dienste
	prefixes := map[string]bool{}
	for _, fc := range failed {
		pres, known := collectorPrefixes(kind)[fc]
		if !known {
			continue
		}
		hit := !noDataCollector(fc)
		for _, p := range pres {
			for k := range c.known {
				if strings.HasPrefix(k, p) && !next[k] {
					next[k] = true // gemerkt lassen
					hit = true
				}
			}
		}
		if !hit {
			quiet = append(quiet, pres...)
			continue
		}
		for _, p := range pres {
			prefixes[p] = true
		}
		if len(errs) < 5 {
			errs = append(errs, clip(fc, 40)+": Sammler des Exporters fehlgeschlagen")
		}
	}
	c.known = next
	if len(errs) == 0 {
		return nil
	}
	for _, p := range quiet {
		prefixes[p] = true
	}
	pe := &apis.PartialError{Errs: errs}
	for p := range prefixes {
		pe.Prefixes = append(pe.Prefixes, p)
	}
	sort.Strings(pe.Prefixes)
	return pe
}

// failedCollectors liefert die ausgefallenen Sammler (sortiert).
func failedCollectors(m *Metrics, kind string) []string {
	var name string
	switch kind {
	case ExporterNode:
		name = "node_scrape_collector_success"
	case ExporterWindows:
		name = "windows_exporter_collector_success"
	default:
		return nil
	}
	set := map[string]bool{}
	for _, s := range m.Get(name) {
		if s.Value == 0 {
			set[s.Label("collector")] = true
		}
	}
	if kind == ExporterNode {
		if v, ok := m.Value("node_textfile_scrape_error"); ok && v > 0 {
			set["textfile"] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// collectorPrefixes: welche Dienste ein Sammler des Exporters liefert.
func collectorPrefixes(kind string) map[string][]string {
	if kind == ExporterWindows {
		return map[string][]string{"cpu": {"cpu"}, "cs": {"cpu", "mem", "swap"}, "memory": {"mem", "swap"},
			"os": {"mem", "swap"}, "pagefile": {"swap"}, "logical_disk": {"fs:"}, "physical_disk": {"disk:"},
			"net": {"if:"}, "service": {"winsvc"}}
	}
	return map[string][]string{"cpu": {"cpu"}, "meminfo": {"mem", "swap"}, "loadavg": {"load"}, "filesystem": {"fs:"},
		"diskstats": {"disk:"}, "netdev": {"if:"}, "bonding": {"bond:"}, "mdadm": {"raid:"}, "zfs": {"zfs:"},
		"hwmon": {"temp:"}, "thermal_zone": {"temp:"}, "systemd": {"systemd"}, "textfile": {"reboot", "updates"}}
}

// detect erkennt den Exporter (build_info, sonst Namensraum der Metriken).
func detect(m *Metrics) (kind, version string) {
	for _, k := range []string{ExporterNode, ExporterWindows} {
		if ss := m.Get(k + "_build_info"); len(ss) > 0 {
			return k, clip(ss[0].Label("version"), 40)
		}
	}
	switch {
	case m.hasPrefix("node_"):
		return ExporterNode, ""
	case m.hasPrefix("windows_"):
		return ExporterWindows, ""
	}
	return ExporterOther, ""
}

func buildReport(m *Metrics, kind string, now time.Time, io winIO) *m64proto.Report {
	switch kind {
	case ExporterNode:
		return nodeReport(m, now)
	case ExporterWindows:
		return windowsReport(m, now, io)
	}
	return nil
}

// Test prueft die Verbindung im Assistenten: Zertifikat (Fingerabdruck), Anmeldung, erkannter Exporter und Zahl der
// Dienste. Aendert den Zustand des Sammlers nicht; die Liste der Dienste (mit Default) liefert danach Collect.
func (c *Collector) Test(ctx context.Context) apis.TestResult {
	var res apis.TestResult
	m, err := c.scrape(ctx)
	ci := c.f.lastCert()
	res.Fingerprint, res.CertSubject, res.Trusted = ci.fp, ci.subject, ci.trusted
	if err != nil {
		res.Error = err.Error()
		res.NeedConfirm = errors.Is(err, ErrUnconfirmed)
		return res
	}
	res.OK = true
	kind, ver := detect(m)
	n := 0
	if rep := buildReport(m, kind, c.now(), nil); rep != nil && c.cfg.Map != nil {
		n = len(c.cfg.Map(nil, rep))
	}
	custom, _ := customServices(m, c.cfg.Metrics, c.now(), nil)
	n += len(custom)
	title := firstNonEmpty(kind, "Unbekannter Exporter")
	res.Version = strings.TrimSpace(title + " " + ver)
	res.Summary = fmt.Sprintf("%s · %d Dienste · %d Serien", title, n, m.Series)
	var warn []string
	if strings.HasPrefix(c.cfg.URL, "http://") && c.cfg.Secret != "" {
		warn = append(warn, "Zugangsdaten werden unverschlüsselt (http) gesendet")
	}
	if kind == ExporterOther && len(c.cfg.Metrics) == 0 {
		warn = append(warn, "Unbekannter Exporter – eigene Metriken eintragen")
	}
	if len(c.cfg.Metrics) > 0 && len(custom) == 0 {
		warn = append(warn, "keine der eigenen Metriken gefunden")
	}
	if fc := failedCollectors(m, kind); len(fc) > 0 {
		var rel []string
		for _, f := range fc {
			if _, ok := collectorPrefixes(kind)[f]; ok && !noDataCollector(f) {
				rel = append(rel, f)
			}
		}
		if len(rel) > 0 {
			warn = append(warn, "Sammler im Exporter fehlgeschlagen: "+strings.Join(limitList(rel, 5), ", "))
		}
	}
	res.Warning = strings.Join(warn, "; ")
	return res
}

// noDataCollector: Sammler, die ohne die Funktion (kein Bond, kein mdraid, kein ZFS) immer als fehlgeschlagen gelten.
func noDataCollector(c string) bool {
	switch c {
	case "bonding", "mdadm", "zfs", "systemd", "thermal_zone", "hwmon":
		return true
	}
	return false
}

// Queries nennt, was abgefragt wird ("Was wird abgefragt?" im Host).
func (c *Collector) Queries() []string {
	q := []string{"GET " + c.cfg.URL + " (Prometheus-Textformat, gzip)",
		"node_exporter: node_cpu_seconds_total, node_memory_*, node_load*, node_filesystem_*, node_disk_*, node_network_*, " +
			"node_bonding_*, node_md_*, node_zfs_zpool_state, node_hwmon_*, node_thermal_zone_temp, node_systemd_unit_state, " +
			"node_reboot_required, apt_upgrades_pending",
		"windows_exporter: windows_cpu_time_*, windows_memory_* (windows_cs_*, windows_os_*), windows_pagefile_*, " +
			"windows_logical_disk_*, windows_physical_disk_*, windows_net_*, windows_service_*, windows_system_boot_time_*"}
	for _, m := range c.cfg.Metrics {
		q = append(q, "eigene Metrik: "+m.Name)
	}
	return q
}

// scrub entfernt das Geheimnis aus einem Fehler (zusaetzliche Sicherung).
func (c *Collector) scrub(err error) error {
	if err == nil || len(c.cfg.Secret) < 4 || !strings.Contains(err.Error(), c.cfg.Secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), c.cfg.Secret, "***"))
}

// --- Hilfen ---

// index baut eine Tabelle Schluessel -> erster endlicher Wert einer Metrik.
func index(m *Metrics, name string, key func(*Sample) string) map[string]float64 {
	ss := m.Get(name)
	out := make(map[string]float64, len(ss))
	for i := range ss {
		if !finite(ss[i].Value) {
			continue
		}
		k := key(&ss[i])
		if _, ok := out[k]; !ok {
			out[k] = ss[i].Value
		}
	}
	return out
}

func hasKey[V any](m map[string]V, k string) bool {
	_, ok := m[k]
	return ok
}

// firstValue: erster vorhandener Name.
func firstValue(m *Metrics, names ...string) (float64, bool) {
	for _, n := range names {
		if v, ok := m.Value(n); ok {
			return v, true
		}
	}
	return 0, false
}

// sum: Summe aller endlichen Werte eines Namens.
func sum(m *Metrics, name string) float64 {
	t := 0.0
	for _, s := range m.Get(name) {
		if finite(s.Value) && s.Value > 0 {
			t += s.Value
		}
	}
	return t
}

// u64: nicht negative, endliche Zahl als uint64 (sonst 0).
func u64(v float64) uint64 {
	if !finite(v) || v <= 0 {
		return 0
	}
	if v >= 1.8e19 {
		return math.MaxUint64
	}
	return uint64(math.Round(v))
}

// ticks: Sekunden -> USER_HZ-Ticks.
func ticks(sec float64) uint64 {
	if !finite(sec) || sec <= 0 || sec > 1e15 {
		return 0
	}
	return uint64(math.Round(sec * userHZ))
}

func firstPos(v ...float64) float64 {
	for _, x := range v {
		if x > 0 {
			return x
		}
	}
	return 0
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

// clip kuerzt Texte vom Host, ersetzt ungueltiges UTF-8 und Steuerzeichen.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > n {
		i := n
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func ptrBool(b bool) *bool      { return &b }
func ptrF64(v float64) *float64 { return &v }
