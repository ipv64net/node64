package monitor64

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

// Uebersetzbare Texte der Sammler (model.T): Schluessel, Sprachdateien, Hinweise der Agents, Texte des Kerns.

var (
	reTextKey  = regexp.MustCompile(`monitor64\.((?:svc|txt|note|snmp)\.[a-z0-9_]+)`)
	reHintCode = regexp.MustCompile(`\{m64:([a-z0-9_]+)`)
	reHintName = regexp.MustCompile(`(?m)^\tHint[A-Za-z]+ += "([a-z0-9_]+)"`)
	rePlaceh   = regexp.MustCompile(`\{[a-z]+\}`)
)

// sourceFiles: Quellen (ohne Tests), in denen Sammler und Agents ihre Texte bauen, dazu die SNMP-Profile und das
// Skript der SSH-Abfrage.
func sourceFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, pat := range []string{"*.go", "apis/*.go", "snmp/*.go", "promscrape/*.go", "model/*.go", "snmp/profiles/*.json",
		"../m64proto/*.go", "../m64linux/*.go", "../m64linux/script.sh", "../m64bsd/*.go", "../m64win/*.go"} {
		files, err := filepath.Glob(pat)
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: keine Dateien (%v)", pat, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") || filepath.Base(f) == "textkeys.go" || filepath.ToSlash(f) == "model/text.go" {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			out[filepath.ToSlash(f)] = string(b)
		}
	}
	return out
}

// Jeder Schluessel, den ein Sammler, ein SNMP-Profil oder ein Hinweis-Code benutzt, steht in collectorTexts (so
// kennt ihn das Skript) und hat einen Text in Deutsch und Englisch mit denselben Platzhaltern; die Liste nennt
// keinen Schluessel, den niemand benutzt.
func TestTextKeys(t *testing.T) {
	b, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]string{}
	src := sourceFiles(t)
	for f, s := range src {
		for _, m := range reTextKey.FindAllStringSubmatch(s, -1) {
			used[m[1]] = f
		}
	}
	// Hinweis-Codes der Agents: jeder Code hat einen Eintrag in noteKeys (sonst zeigt die Node ihn roh)
	codes := map[string]string{}
	for f, s := range src {
		if !strings.HasPrefix(f, "../") {
			continue
		}
		for _, m := range reHintCode.FindAllStringSubmatch(s, -1) {
			codes[m[1]] = f
		}
	}
	for _, m := range reHintName.FindAllStringSubmatch(src["../m64proto/hint.go"], -1) {
		codes[m[1]] = "../m64proto/hint.go"
	}
	if len(codes) < 30 {
		t.Fatalf("nur %d Hinweis-Codes gefunden", len(codes))
	}
	for c, f := range codes {
		key, ok := noteKeys[c]
		if !ok {
			t.Errorf("Hinweis-Code %q (%s) fehlt in noteKeys", c, f)
		} else if key != "monitor64.note."+c {
			t.Errorf("noteKeys[%q] = %q", c, key)
		}
	}
	for c := range noteKeys {
		if _, ok := codes[c]; !ok {
			t.Errorf("noteKeys nennt den Code %q, den kein Agent sendet", c)
		}
	}
	if len(used) < 400 {
		t.Fatalf("nur %d Schluessel in den Quellen gefunden", len(used))
	}
	listed := map[string]bool{}
	for _, k := range collectorTexts {
		if listed[k] {
			t.Errorf("collectorTexts: %s doppelt", k)
		}
		listed[k] = true
		if _, ok := used[k]; !ok {
			t.Errorf("collectorTexts: %s wird nirgends benutzt", k)
		}
	}
	if !sort.StringsAreSorted(collectorTexts) {
		t.Error("collectorTexts ist nicht sortiert")
	}
	var missing []string
	for k, f := range used {
		if !listed[k] {
			missing = append(missing, k+" ("+f+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("in collectorTexts (textkeys.go) fehlen:\n  %s", strings.Join(missing, "\n  "))
	}
	for k := range used {
		de, en := b.T("de", "monitor64."+k), b.T("en", "monitor64."+k)
		if de == "monitor64."+k || en == "monitor64."+k {
			t.Errorf("monitor64.%s: Text fehlt (de %v, en %v)", k, de != "monitor64."+k, en != "monitor64."+k)
			continue
		}
		pd, pe := rePlaceh.FindAllString(de, -1), rePlaceh.FindAllString(en, -1)
		sort.Strings(pd)
		sort.Strings(pe)
		if strings.Join(pd, "") != strings.Join(pe, "") {
			t.Errorf("monitor64.%s: Platzhalter verschieden: %q / %q", k, de, en)
		}
	}
	// alles, was das Skript uebersetzen soll, kommt mit der Seite (coreTexts)
	core := map[string]bool{}
	for _, k := range coreTexts {
		core[k] = true
	}
	for _, k := range append([]string{"detail.threshold", "detail.threshold_free", "detail.access", "unit.days", "unit.min", "kind.mem_used",
		"kind.fs_trend_days", "access.docker", "access.snmp", "access.agent"}, collectorTexts...) {
		if !core[k] {
			t.Errorf("coreTexts ohne %s", k)
		}
	}
}

// Hinweise der Agents: Codes werden uebersetzbar, alte deutsche Texte und freie Meldungen bleiben, fremde Token
// werden entschaerft.
func TestHostText(t *testing.T) {
	for in, want := range map[string][2]string{
		m64proto.HintReading:                              {"wird gelesen", "still being read"},
		"smartctl: " + m64proto.HintTimeout:               {"smartctl: Zeitlimit", "smartctl: timeout"},
		m64proto.Hint(m64proto.HintMissing, "smartctl"):   {"smartctl fehlt", "smartctl not found"},
		"statfs /mnt/nfs: " + m64proto.Hint("hung", "5s"): {"statfs /mnt/nfs: hängt seit 5s", "statfs /mnt/nfs: hung for 5s"},
		m64proto.HintSecUnknown + ": dnf: " + m64proto.Hint(m64proto.HintExitCode, "3"): {"Sicherheitsupdates unbekannt: dnf: Exit-Code 3",
			"security updates unknown: dnf: exit code 3"},
		m64proto.Hint(m64proto.HintTooLarge, "5000000", "4194304"): {"Ausgabe zu groß (5000000 Bytes, höchstens 4194304)",
			"output too large (5000000 bytes, max. 4194304)"},
		m64proto.HintTimeout + "abc":               {"Zeitlimit abc", "timeout abc"}, // Text direkt hinter dem Code: Abstand statt kaputtem Token
		m64proto.HintTimeout + m64proto.HintFormat: {"Zeitlimit unbekanntes Format", "timeout unknown format"},
		"smartctl fehlt":                           {"smartctl fehlt", "smartctl fehlt"}, // aelterer Agent: bleibt, wie er ist
		"open /proc/stat: no such file":            {"open /proc/stat: no such file", "open /proc/stat: no such file"},
		"{m64:spaeter=1}":                          {"{m64:spaeter=1}", "{m64:spaeter=1}"}, // Code einer neueren Version
		"i18n:monitor64.state.crit":                {"i18n: monitor64.state.crit", "i18n: monitor64.state.crit"},
		"":                                         {"", ""},
	} {
		got := hostText(in)
		if de, en := modeltest.DE(got), modeltest.EN(got); de != want[0] || en != want[1] {
			t.Errorf("%q: de %q, en %q", in, de, en)
		}
	}
	// Abschnittsfehler und Hinweise eines Berichts werden genau einmal umgesetzt
	rep := &m64proto.Report{Time: 1000, Errors: []m64proto.SectionErr{{Section: "smart", Error: "smartctl: " + m64proto.HintNotFound}},
		Notes: []m64proto.SectionNote{{Section: "updates", Note: m64proto.HintNoPkgManager}}}
	MapReport(nil, rep)
	MapReport(nil, rep)
	if modeltest.EN(rep.Errors[0].Error) != "smartctl: program not found" || modeltest.DE(rep.Notes[0].Note) != "kein Paketverwalter erkannt" {
		t.Fatalf("Bericht: %+v", rep)
	}
	if err := sectionErrors(rep); err == nil || !strings.Contains(modeltest.EN(err.Error()), "smart: smartctl: program not found") {
		t.Fatalf("Teilfehler: %v", err)
	}
}

// hostile fuellt alle Textfelder eines Werts mit s (Felder mit festen Werten wie Health bleiben moeglich: es zaehlt
// nur, dass nichts eingeschleust wird).
func hostile(v reflect.Value, s string) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		hostile(v.Elem(), s)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				hostile(v.Field(i), s)
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		v.Set(reflect.MakeSlice(v.Type(), 2, 2))
		for i := 0; i < v.Len(); i++ {
			hostile(v.Index(i), s)
		}
	case reflect.String:
		v.SetString(s)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(3)
	case reflect.Uint64:
		v.SetUint(7)
	case reflect.Float64:
		v.SetFloat(1.5)
	}
}

// Ein Host darf ueber keinen Text seines Berichts (Namen von Platten, Pools, Schnittstellen, Diensten, eigene
// Skripte, Fehlermeldungen) ein eigenes Token einschleusen: nach dem Abbilden steht der Text als Text da.
func TestMapReportNoInjection(t *testing.T) {
	const evil = "i18n:monitor64.state.crit"
	for _, s := range []string{evil, "x " + evil + " y", evil + "?name=" + evil, "{m64:reading} " + evil} {
		prev, cur := &m64proto.Report{}, &m64proto.Report{}
		hostile(reflect.ValueOf(prev), s)
		hostile(reflect.ValueOf(cur), s)
		prev.Time, cur.Time = 1_000_000, 1_060_000
		svcs := MapReport(prev, cur)
		if len(svcs) < 15 {
			t.Fatalf("nur %d Dienste: %+v", len(svcs), svcs)
		}
		check := func(what, text string) {
			for _, k := range model.Keys(text) {
				if k == "monitor64.state.crit" {
					t.Errorf("%q: %s enthaelt ein Token des Hosts: %q", s, what, text)
				}
			}
			if strings.Contains(modeltest.DE(text), "Kritisch") {
				t.Errorf("%q: %s uebersetzt den Text des Hosts: %q", s, what, modeltest.DE(text))
			}
		}
		for _, sv := range svcs {
			check(sv.Key+" Name", sv.Name)
			check(sv.Key+" Text", sv.Text)
			for _, f := range sv.Facts {
				check(sv.Key+" Fact "+f.Code, f.Text)
			}
		}
		for _, e := range cur.Errors {
			check("Fehler "+e.Section, e.Error)
		}
		for _, n := range cur.Notes {
			check("Hinweis "+n.Section, n.Note)
		}
		if err := sectionErrors(cur); err != nil {
			check("Teilfehler", err.Error())
		}
	}
}

// Dienstnamen und Texte des Mappers in beiden Sprachen; Eigennamen und Groessen bleiben.
func TestMapReportLanguages(t *testing.T) {
	cur := &m64proto.Report{Time: 1000, CPU: &m64proto.CPU{Cores: 8},
		Mem:     &m64proto.Mem{Total: 16_000_000_000, Available: 4_000_000_000},
		FS:      []m64proto.FS{{Mount: "/", Type: "ext4", Total: 100_000_000_000, Used: 60_000_000_000, Avail: 40_000_000_000, ReadOnly: true}},
		ZFS:     []m64proto.ZPool{{Name: "tank", Health: "ONLINE", Size: 10_000_000_000_000, Alloc: 7_000_000_000_000, Free: 3_000_000_000_000}},
		Temps:   []m64proto.Temp{{Name: "coretemp/0", Label: "Package id 0", C: 45}},
		Systemd: &m64proto.Systemd{Failed: []string{"nginx.service"}},
		Updates: &m64proto.Updates{Pending: 12, Security: 3},
		Reboot:  &m64proto.Reboot{Required: true, Packages: []string{"linux-image"}},
		SMART:   []m64proto.SMART{{Device: "/dev/sda", Serial: "S1", Error: m64proto.Hint(m64proto.HintNoOutputOf, "smartctl")}},
	}
	svcs := MapReport(nil, cur)
	for key, want := range map[string][4]string{
		"cpu":             {"CPU", "CPU", "8 Kerne", "cores: 8"},
		"mem":             {"RAM", "RAM", "4,0 GB von 16,0 GB frei", "4.0 GB of 16.0 GB free"},
		"fs:/":            {"Dateisystem /", "Filesystem /", "40,0 GB von 100,0 GB frei · nur lesbar", "40.0 GB of 100.0 GB free · read-only"},
		"zfs:tank":        {"ZFS tank", "ZFS tank", "ONLINE · 3,0 TB frei", "ONLINE · 3.0 TB free"},
		"temp:coretemp/0": {"Temperatur Package id 0", "Temperature Package id 0", "", ""},
		"systemd":         {"systemd-Dienste", "systemd services", "1 fehlgeschlagen: nginx.service", "1 failed: nginx.service"},
		"updates":         {"Updates", "Updates", "12 verfügbar, 3 Sicherheitsupdates", "12 available, 3 security updates"},
		"reboot":          {"Neustart nötig", "Reboot required", "ja", "yes"},
		"disk:S1":         {"sda", "sda", "SMART nicht lesbar", "SMART unreadable"},
	} {
		s := svcBy(svcs, key)
		if s == nil {
			t.Errorf("%s fehlt", key)
			continue
		}
		got := [4]string{modeltest.DE(s.Name), modeltest.EN(s.Name), modeltest.DE(s.Text), modeltest.EN(s.Text)}
		if got != want {
			t.Errorf("%s = %q, erwartet %q", key, got, want)
		}
	}
	if f := svcBy(svcs, "disk:S1").Facts; len(f) != 1 || modeltest.EN(f[0].Text) != "no output from smartctl" || modeltest.DE(f[0].Text) != "keine Ausgabe von smartctl" {
		t.Errorf("SMART-Fehler: %+v", f)
	}
}

// Ursache bei ueberschrittener Schwelle: Bezeichnung der Regel-Art, gerundeter Wert und Schwelle mit Einheit.
func TestDescribe(t *testing.T) {
	st := func(v, limit float64) eval.Status { return eval.Status{Value: v, Threshold: eval.Limit{V: limit}} }
	for _, c := range []struct {
		ms     eval.MetricStatus
		kind   string
		free   bool
		de, en string
	}{
		{eval.MetricStatus{Name: "used", Status: st(92.05, 90)}, eval.KindMemUsed, false, "RAM belegt 92 % (Schwelle 90 %)", "RAM used 92 % (threshold 90 %)"},
		{eval.MetricStatus{Name: "used", Status: st(80.87, 80)}, eval.KindFSUsed, false,
			"Dateisystem / Laufwerk belegt 81 % (Schwelle 80 %)", "File system / drive used 81 % (threshold 80 %)"},
		{eval.MetricStatus{Name: "used", Status: st(12.44, 20)}, eval.KindFSUsed, true, "nur noch 12 GB frei (Schwelle 20 GB)", "only 12 GB free (threshold 20 GB)"},
		{eval.MetricStatus{Name: "per_core", Status: st(1.26, 1)}, eval.KindLoadCore, false, "Load je Kern 1.3 (Schwelle 1)", "Load per core 1.3 (threshold 1)"},
		{eval.MetricStatus{Name: "trend_days", Status: st(3.2, 7)}, eval.KindFSTrendDays, false,
			"Trend: voll in weniger als 3.2 Tage (Schwelle 7 Tage)", "Trend: full in less than 3.2 days (threshold 7 days)"},
		{eval.MetricStatus{Name: "runtime", Status: st(540, 600)}, eval.KindUPSRuntime, false,
			"USV-Restlaufzeit (unter) 9 Min. (Schwelle 10 Min.)", "UPS runtime (below) 9 min (threshold 10 min)"},
		{eval.MetricStatus{Name: "temp", Status: st(71.4, 70)}, eval.KindTempSystem, false,
			"Temperatur (System/CPU) 71 °C (Schwelle 70 °C)", "Temperature (system/CPU) 71 °C (threshold 70 °C)"},
		{eval.MetricStatus{Name: "errrate", Status: st(0.25, 0.1)}, eval.KindIfErrRate, false,
			"Port-Fehlerrate 0.25 % (Schwelle 0.1 %)", "Port error rate 0.25 % (threshold 0.1 %)"},
		// Zustandsregel ohne Text des Sammlers: Bezeichnung der Regel statt des rohen Namens
		{eval.MetricStatus{Name: eval.KindRAIDDegraded, Status: eval.Status{Threshold: eval.Limit{Off: true}}}, "", false, "RAID / ZFS degraded", "RAID / ZFS degraded"},
		// unbekannte Messgroesse: Name bleibt (entschaerft)
		{eval.MetricStatus{Name: "i18n:monitor64.state.crit", Status: st(5, 4)}, "", false, "i18n: monitor64.state.crit 5 (Schwelle 4)",
			"i18n: monitor64.state.crit 5 (threshold 4)"},
	} {
		got := describe(c.ms, c.kind, c.free)
		if de, en := modeltest.DE(got), modeltest.EN(got); de != c.de || en != c.en {
			t.Errorf("%s/%s: de %q, en %q", c.ms.Name, c.kind, de, en)
		}
	}
	for v, want := range map[float64]string{92.05: "92", 80.87: "81", 9.96: "10", 1.26: "1.3", 1: "1", 0.25: "0.25", 0.104: "0.1", 0: "0", -3.44: "-3.4"} {
		if got := shortNum(v); got != want {
			t.Errorf("shortNum(%v) = %q, erwartet %q", v, got, want)
		}
	}
}

// Der Zugangs-Dienst heisst je Art ("Zugang Docker-API"), uebersetzbar; unbekannte Arten bleiben "API".
func TestAccessName(t *testing.T) {
	for typ, want := range map[string][2]string{
		"docker": {"Zugang Docker-API", "Access Docker API"}, "pve": {"Zugang Proxmox VE", "Access Proxmox VE"},
		"snmp": {"Zugang SNMP", "Access SNMP"}, "truenas": {"Zugang TrueNAS", "Access TrueNAS"}, "ssh": {"Zugang SSH", "Access SSH"},
		"agent": {"Zugang Agent", "Access Agent"}, "prom": {"Zugang Prometheus", "Access Prometheus"}, "foo": {"Zugang API", "Access API"},
	} {
		name := model.T("monitor64.detail.access", "name", model.Sub(accessName(typ)))
		if de, en := modeltest.DE(name), modeltest.EN(name); de != want[0] || en != want[1] {
			t.Errorf("%s: de %q, en %q", typ, de, en)
		}
	}
	for _, typ := range accessTypes {
		if n := accessName(typ); modeltest.DE(n) == "" || len(model.Keys(modeltest.DE(n))) != 0 || strings.Contains(modeltest.DE(n), "access.") {
			t.Errorf("%s: %q", typ, modeltest.DE(n))
		}
	}
}

// CSV und Suche uebersetzen zusammengesetzte Texte in der Sprache der Anfrage (gleiche Funktion wie die Meldungen).
func TestTxReq(t *testing.T) {
	b, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{}
	lang := "en"
	m.g.T = func(_ *http.Request, key string, args ...any) string { return b.T(lang, key, args...) }
	r := httptest.NewRequest("GET", "/", nil)
	name := model.T("monitor64.svc.fs", "name", "/var")
	text := "ONLINE · " + model.T("monitor64.txt.free", "v", "3,0 GB") + " · " + model.T("monitor64.txt.readonly")
	if got := m.txReq(r, name); got != "Filesystem /var" {
		t.Errorf("en Name = %q", got)
	}
	if got := m.txReq(r, text); got != "ONLINE · 3.0 GB free · read-only" {
		t.Errorf("en Text = %q", got)
	}
	lang = "de"
	if got := m.txReq(r, name+" ↓"); got != "Dateisystem /var ↓" {
		t.Errorf("de Name = %q", got)
	}
	if got := m.txReq(r, "Arbeitsspeicher"); got != "Arbeitsspeicher" {
		t.Errorf("alter Name = %q", got)
	}
	m.g.T = nil
	if got := m.txReq(r, name); got != name {
		t.Errorf("ohne Uebersetzer = %q", got)
	}
}
