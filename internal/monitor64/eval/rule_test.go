package eval

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStateOrderAndText(t *testing.T) {
	if !Crit.Worse(Unknown) || !Unknown.Worse(Warn) || !Warn.Worse(OK) || OK.Worse(OK) {
		t.Fatal("Reihenfolge OK < Warn < Unknown < Crit stimmt nicht")
	}
	if got := Worst(); got != OK {
		t.Fatalf("Worst() = %v", got)
	}
	if got := Worst(Warn, Unknown, OK); got != Unknown {
		t.Fatalf("Worst = %v", got)
	}
	if Unknown.NotifySeverity() != Warn || Crit.NotifySeverity() != Crit {
		t.Fatal("NotifySeverity")
	}
	for _, s := range []State{OK, Warn, Crit, Unknown} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var back State
		if err := json.Unmarshal(b, &back); err != nil || back != s {
			t.Fatalf("%v -> %s -> %v (%v)", s, b, back, err)
		}
	}
	var s State
	if json.Unmarshal([]byte(`"kaputt"`), &s) == nil {
		t.Fatal("unbekannter Zustand ohne Fehler")
	}
	if _, err := State(9).MarshalText(); err == nil {
		t.Fatal("ungueltiger Zustand ohne Fehler")
	}
}

func TestRuleJSON(t *testing.T) {
	in := `{"warn":85,"crit":"off","for":300,"hyst":1.5,"mode":"free","report":"show","dir":"down"}`
	var r Rule
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	if r.Warn == nil || r.Warn.V != 85 || r.Warn.Off || r.Crit == nil || !r.Crit.Off {
		t.Fatalf("Limits falsch: %+v %+v", r.Warn, r.Crit)
	}
	if time.Duration(*r.For) != 5*time.Minute || *r.Hyst != 1.5 || *r.Mode != ModeFree || *r.Report != ReportShow || *r.Dir != Down {
		t.Fatalf("Felder falsch: %+v", r)
	}
	if r.WarnFree != nil || r.Severity != nil {
		t.Fatal("nicht gesetzte Felder muessen nil bleiben (erben)")
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Rule
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	out2, _ := json.Marshal(back)
	if string(out) != string(out2) {
		t.Fatalf("Rundreise: %s != %s", out, out2)
	}
	for _, bad := range []string{`{"warn":"x"}`, `{"mode":"bytes"}`, `{"for":-1}`, `{"severity":"egal"}`, `{"dir":"links"}`, `{"report":"nie"}`} {
		var r Rule
		if json.Unmarshal([]byte(bad), &r) == nil {
			t.Errorf("%s ohne Fehler", bad)
		}
	}
	if (Rule{Hyst: F(-1)}).Validate() == nil || (Rule{For: D(-time.Second)}).Validate() == nil {
		t.Fatal("Validate laesst negative Werte durch")
	}
	if (Rule{Warn: L(1), Hyst: F(0)}).Validate() != nil {
		t.Fatal("Validate lehnt gueltige Regel ab")
	}
	if !(Rule{}).Empty() || (Rule{Warn: L(1)}).Empty() {
		t.Fatal("Empty")
	}
}

func TestResolveStages(t *testing.T) {
	std := Defaults()
	host := HostRef{ID: "h1", Name: "nas01", Group: "Keller", Tags: []string{"NAS", "backup"}}
	ovs := []Override{
		{ID: "o-cpu", Group: "keller", Kind: KindCPUUtil, Rule: Rule{Warn: L(70)}},             // andere Art
		{ID: "o1", Tag: "nas", Kind: KindFSUsed, Rule: Rule{Warn: L(85), For: D(time.Minute)}}, // passt (Tag)
		{ID: "o2", Group: "Keller", Kind: KindFSUsed, Rule: Rule{Crit: L(99), Hyst: F(5)}},     // passt auch, aber unten
	}

	t.Run("nur Standard", func(t *testing.T) {
		e := Resolve(std, nil, host, HostLevel{}, KindFSUsed)
		if !e.Known || e.IsState || e.Warn.V != 80 || e.Crit.V != 90 || e.Dir != Up || e.Hyst != 2 || e.Override != -1 {
			t.Fatalf("%+v", e)
		}
		for f, st := range e.Origin {
			if st != StageDefault {
				t.Errorf("%s kommt aus %s", f, st)
			}
		}
	})

	t.Run("oben gewinnt, kein Mischen", func(t *testing.T) {
		e := Resolve(std, ovs, host, HostLevel{}, KindFSUsed)
		if e.Override != 1 || e.OverrideID != "o1" {
			t.Fatalf("Abweichung %d %q", e.Override, e.OverrideID)
		}
		if e.Warn.V != 85 || time.Duration(e.For) != time.Minute {
			t.Fatalf("Felder aus o1 fehlen: %+v", e)
		}
		// Crit und Hyst aus o2 duerfen nicht gemischt werden: sie erben vom Standard.
		if e.Crit.V != 90 || e.Hyst != 2 {
			t.Fatalf("o2 wurde gemischt: crit=%v hyst=%v", e.Crit, e.Hyst)
		}
		if e.Origin[FieldWarn] != StageOverride || e.Origin[FieldFor] != StageOverride || e.Origin[FieldCrit] != StageDefault {
			t.Fatalf("Herkunft %v", e.Origin)
		}
	})

	t.Run("Host Art und Dienst, Feld fuer Feld", func(t *testing.T) {
		hl := HostLevel{
			Kind:    &Rule{Warn: L(88), Crit: L(95)},
			Service: &Rule{Crit: LOff(), Report: ptr(ReportShow)},
		}
		e := Resolve(std, ovs, host, hl, KindFSUsed)
		if e.Warn.V != 88 || !e.Crit.Off || e.Report != ReportShow || time.Duration(e.For) != time.Minute {
			t.Fatalf("%+v", e)
		}
		want := map[string]Stage{FieldWarn: StageHostKind, FieldCrit: StageService, FieldReport: StageService,
			FieldFor: StageOverride, FieldHyst: StageDefault}
		for f, st := range want {
			if e.Origin[f] != st {
				t.Errorf("%s: %s, erwartet %s", f, e.Origin[f], st)
			}
		}
		if e.Notify() {
			t.Fatal("nur anzeigen meldet")
		}
	})

	t.Run("kein Treffer ohne Bedingung", func(t *testing.T) {
		e := Resolve(std, []Override{{Kind: KindFSUsed, Rule: Rule{Warn: L(1)}}}, host, HostLevel{}, KindFSUsed)
		if e.Override != -1 || e.Warn.V != 80 {
			t.Fatalf("Abweichung ohne Gruppe/Tag hat gegriffen: %+v", e)
		}
	})

	t.Run("Gruppe und Tag zusammen muessen beide passen", func(t *testing.T) {
		o := []Override{{Group: "Keller", Tag: "web", Kind: KindFSUsed, Rule: Rule{Warn: L(1)}}}
		if e := Resolve(std, o, host, HostLevel{}, KindFSUsed); e.Override != -1 {
			t.Fatal("Tag passt nicht, trotzdem Treffer")
		}
		o[0].Tag = "Backup"
		if e := Resolve(std, o, host, HostLevel{}, KindFSUsed); e.Override != 0 {
			t.Fatal("Gruppe und Tag passen, aber kein Treffer")
		}
	})

	t.Run("unbekannte Art", func(t *testing.T) {
		e := Resolve(std, nil, host, HostLevel{}, "foo.bar")
		if e.Known || !e.Warn.Off || !e.Crit.Off || e.Report != ReportNotify {
			t.Fatalf("%+v", e)
		}
	})

	t.Run("Zustandsregel", func(t *testing.T) {
		e := Resolve(std, nil, host, HostLevel{Service: &Rule{Severity: ptr(SevWarn)}}, KindSmartFailed)
		if !e.IsState || e.Severity != SevWarn || e.Origin[FieldSeverity] != StageService {
			t.Fatalf("%+v", e)
		}
		w, c, dir, h := e.Levels()
		if w.Off || w.V != 1 || !c.Off || dir != Up || h != 0 {
			t.Fatalf("Levels %v %v %v %v", w, c, dir, h)
		}
		// Severity bei Zahlenwerten wird ignoriert
		e = Resolve(std, nil, host, HostLevel{Service: &Rule{Severity: ptr(SevCrit)}}, KindCPUUtil)
		if e.Severity != "" {
			t.Fatal("Severity bei Zahlenwert uebernommen")
		}
	})

	t.Run("Modus GB frei", func(t *testing.T) {
		e := Resolve(std, nil, host, HostLevel{Kind: &Rule{Mode: ptr(ModeFree), WarnFree: L(500), CritFree: L(100)}}, KindStoreUsed)
		w, c, dir, _ := e.Levels()
		if w.V != 500 || c.V != 100 || dir != Down {
			t.Fatalf("%v %v %v", w, c, dir)
		}
	})
}

func TestDefaultsTable(t *testing.T) {
	std := Defaults()
	cases := []struct {
		kind       string
		warn, crit float64 // -1 = aus
		dir        Direction
		dur        time.Duration
	}{
		{KindFSUsed, 80, 90, Up, 0},
		{KindStoreUsed, 80, 90, Up, 0},
		{KindMemUsed, 80, 90, Up, 5 * time.Minute},
		{KindGuestMem, -1, -1, Up, 5 * time.Minute}, // nur Anzeige: Proxmox zaehlt den Cache des Gastes mit
		{KindSwapUsed, 50, 80, Up, 5 * time.Minute},
		{KindCPUUtil, 90, 95, Up, 15 * time.Minute},
		{KindLoadCore, 2, 4, Up, 15 * time.Minute},
		{KindDiskTemp, 50, 60, Up, 5 * time.Minute},
		{KindDiskTempNVMe, 70, 80, Up, 5 * time.Minute},
		{KindSSDWear, 80, 90, Up, 0},
		{KindIfUtil, 80, 90, Up, 5 * time.Minute},
		{KindIfErrRate, 0.01, 0.1, Up, 5 * time.Minute},
		{KindFSTrendDays, 7, 2, Down, 0},
		{KindPrinterSupply, 15, 5, Down, 0},
		{KindUPSRuntime, -1, 600, Down, 0}, // Warnung = auf Batterie (eigene Zustandsregel)
		{KindPoEUsed, 85, 95, Up, 5 * time.Minute},
		{KindMailQueue, 100, 500, Up, 10 * time.Minute},
		{KindTempSystem, 70, 80, Up, 5 * time.Minute},
	}
	for _, c := range cases {
		e := Resolve(std, nil, HostRef{}, HostLevel{}, c.kind)
		if !e.Known || e.IsState {
			t.Errorf("%s: unbekannt oder Zustandsregel", c.kind)
			continue
		}
		chk := func(name string, l Limit, want float64) {
			if want < 0 {
				if !l.Off {
					t.Errorf("%s %s: %v, erwartet aus", c.kind, name, l)
				}
			} else if l.Off || l.V != want {
				t.Errorf("%s %s: %v, erwartet %v", c.kind, name, l, want)
			}
		}
		chk("warn", e.Warn, c.warn)
		chk("crit", e.Crit, c.crit)
		if e.Dir != c.dir || time.Duration(e.For) != c.dur || e.Mode != ModeUsed || e.Report != ReportNotify {
			t.Errorf("%s: %+v", c.kind, e)
		}
		if err := e.Validate(); err != nil {
			t.Errorf("%s: %v", c.kind, err)
		}
		if e.Hyst <= 0 {
			t.Errorf("%s: Hysterese %v", c.kind, e.Hyst)
		}
	}
	states := map[string]struct {
		sev Severity
		dur time.Duration
	}{
		KindSmartFailed: {SevCrit, 0}, KindSmartSectors: {SevWarn, 0}, KindSmartSectorsUp: {SevCrit, 0},
		KindRAIDDegraded: {SevCrit, 0}, KindBondMemberDown: {SevWarn, 0}, KindBondLACP: {SevWarn, 0},
		KindUPSOnBattery: {SevWarn, 0}, KindUpdatesSecurity: {SevWarn, 24 * time.Hour},
		KindRebootRequired: {SevWarn, 24 * time.Hour}, KindGuestDown: {SevCrit, 0}, KindSystemdFailed: {SevWarn, 0}, KindWinSvcStopped: {SevWarn, 5 * time.Minute},
		KindUPSLowBattery: {SevCrit, 0}, KindUPSReplace: {SevWarn, 0}, KindUPSOverload: {SevWarn, 0},
		KindDeviceWarn: {SevWarn, 0}, KindDeviceCrit: {SevCrit, 0}, KindParityErrors: {SevWarn, 0},
		KindHostRestarted: {SevWarn, 0}, KindIfDown: {SevWarn, 0}, KindIfSpeedLow: {SevWarn, 0}, KindIfHalfDuplex: {SevWarn, 0},
		KindUPSAlarm: {SevWarn, 0}, KindPrinterError: {SevWarn, 0}, KindPaperEmpty: {SevWarn, 0}, KindHWFailed: {SevCrit, 0},
		KindPoEFault: {SevWarn, 0}, KindTrapReceived: {SevWarn, 0},
		KindServiceGone: {SevWarn, 0}, KindAccessFailed: {SevWarn, 0},
		KindCtrUnhealthy: {SevWarn, 0}, KindBackupOld: {SevWarn, 0}, KindJobFailed: {SevWarn, 0},
		KindStoreInactive: {SevCrit, 0}, KindClusterQuorum: {SevCrit, 0}, KindClusterNodeDown: {SevWarn, 0},
		KindHAError: {SevWarn, 0}, KindCephWarn: {SevWarn, 0}, KindCephErr: {SevCrit, 0},
	}
	for k, want := range states {
		e := Resolve(std, nil, HostRef{}, HostLevel{}, k)
		if !e.IsState || e.Severity != want.sev || time.Duration(e.For) != want.dur {
			t.Errorf("%s: %+v", k, e)
		}
	}
	if len(std) != len(cases)+len(states) {
		t.Errorf("Tabelle hat %d Arten, getestet %d", len(std), len(cases)+len(states))
	}
	// Neue Tabelle je Aufruf
	std[KindFSUsed] = Rule{}
	if Defaults()[KindFSUsed].Warn == nil {
		t.Fatal("Defaults teilt Speicher")
	}
}

func TestEffectiveValidate(t *testing.T) {
	std := Defaults()
	e := Resolve(std, nil, HostRef{}, HostLevel{Service: &Rule{Warn: L(95)}}, KindFSUsed)
	if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "ueber Kritisch") {
		t.Fatalf("Warnung > Kritisch nicht erkannt: %v", err)
	}
	e = Resolve(std, nil, HostRef{}, HostLevel{Service: &Rule{Warn: L(3)}}, KindPrinterSupply)
	if err := e.Validate(); err == nil {
		t.Fatal("unten: Warnung < Kritisch nicht erkannt")
	}
	e = Resolve(std, nil, HostRef{}, HostLevel{Service: &Rule{Crit: LOff(), Warn: L(99)}}, KindFSUsed)
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEffectiveJSON(t *testing.T) {
	e := Resolve(Defaults(), nil, HostRef{}, HostLevel{}, KindUPSRuntime)
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"warn":"off"`) || !strings.Contains(string(b), `"crit":600`) {
		t.Fatalf("%s", b)
	}
}

func ptr[T any](v T) *T { return &v }

// F5-K1: jede Art hat eigene Zeiger; Ueberlagern einer Art aendert keine andere.
func TestRuleOverlayAndClone(t *testing.T) {
	// Nachbau des alten Kerns: gespeicherte Felder per Unmarshal in die Standard-Regel einer Art.
	std := Defaults()
	base := std[KindFSUsed]
	if err := json.Unmarshal([]byte(`{"report":"show","mode":"free","warn_free":100,"crit_free":10}`), &base); err != nil {
		t.Fatal(err)
	}
	std[KindFSUsed] = base
	for _, k := range []string{KindCPUUtil, KindMemUsed, KindSmartFailed, KindStoreUsed} {
		if e := Resolve(std, nil, HostRef{ID: "h"}, HostLevel{}, k); e.Mode != ModeUsed || e.Report != ReportNotify {
			t.Fatalf("%s: Aenderung an fs.used wirkt mit: %+v", k, e)
		}
	}

	// Overlay: gesetzte Felder gewinnen, Rest bleibt, keine geteilten Zeiger.
	std = Defaults()
	var saved Rule
	if err := json.Unmarshal([]byte(`{"report":"show","warn":70}`), &saved); err != nil {
		t.Fatal(err)
	}
	orig := std[KindFSUsed]
	got := orig.Overlay(saved)
	if got.Warn.V != 70 || got.Crit.V != 90 || *got.Report != ReportShow || *got.Mode != ModeUsed || *got.Dir != Up {
		t.Fatalf("Overlay: %+v", got)
	}
	if got.Warn == saved.Warn || got.Crit == orig.Crit || got.Mode == orig.Mode || got.Report == saved.Report {
		t.Fatal("Overlay teilt Zeiger")
	}
	if orig.Warn.V != 80 || *orig.Report != ReportNotify {
		t.Fatalf("Overlay aendert die Basis: %+v", orig)
	}
	std[KindFSUsed] = got
	*got.Mode = ModeFree
	if e := Resolve(std, nil, HostRef{}, HostLevel{}, KindStoreUsed); e.Mode != ModeUsed || e.Report != ReportNotify {
		t.Fatalf("store.used veraendert: %+v", e)
	}
	if (Rule{}).Overlay(Rule{}) != (Rule{}) {
		t.Fatal("leere Regeln")
	}

	// Clone ist tief: Aenderungen an der Kopie wirken nicht zurueck.
	a := Defaults()
	b := a.Clone()
	*b[KindCPUUtil].Mode = ModeFree
	b[KindCPUUtil].Warn.V = 1
	*b[KindSmartFailed].Severity = SevOff
	if *a[KindCPUUtil].Mode != ModeUsed || a[KindCPUUtil].Warn.V != 90 || *a[KindSmartFailed].Severity != SevCrit {
		t.Fatal("Clone teilt Zeiger")
	}
	if Table(nil).Clone() != nil || len(b) != len(a) {
		t.Fatal("Clone Laenge/nil")
	}
	// Keine zwei Arten der Standard-Tabelle teilen einen Zeiger.
	seen := map[any]string{}
	for k, r := range Defaults() {
		for _, p := range []any{r.Warn, r.Crit, r.WarnFree, r.CritFree, r.Dir, r.For, r.Hyst, r.Mode, r.Report, r.Severity} {
			if v := reflectPtr(p); v != nil {
				if o, ok := seen[v]; ok {
					t.Fatalf("%s und %s teilen einen Zeiger", k, o)
				}
				seen[v] = k
			}
		}
	}
}

// reflectPtr liefert den Zeiger als vergleichbaren Wert (nil-Zeiger -> nil).
func reflectPtr(p any) any {
	switch v := p.(type) {
	case *Limit:
		if v != nil {
			return v
		}
	case *Direction:
		if v != nil {
			return v
		}
	case *Dur:
		if v != nil {
			return v
		}
	case *float64:
		if v != nil {
			return v
		}
	case *Mode:
		if v != nil {
			return v
		}
	case *Report:
		if v != nil {
			return v
		}
	case *Severity:
		if v != nil {
			return v
		}
	}
	return nil
}
