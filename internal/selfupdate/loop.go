package selfupdate

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

// Einstellungen (Kern-Settings).
const (
	SetMode    = "updates.mode"    // off | notify | auto
	SetChannel = "updates.channel" // stable | preview
	SetWindow  = "updates.window"  // Zeitfenster fuer "auto", z. B. 03:00-05:00 (Zeitzone der Node)
	SetLatest  = "updates.latest"  // letztes Pruefergebnis (JSON, Anzeige)
	setCheck   = "updates.check"   // alt: "1" = nur pruefen
)

// Modes: Betriebsarten.
var Modes = []string{"off", "notify", "auto"}

// Getter liest eine Einstellung.
type Getter func(key, def string) string

// Mode: Betriebsart (Standard aus; die alte Einstellung "nur pruefen" zaehlt als notify).
func Mode(get Getter) string {
	switch m := get(SetMode, ""); m {
	case "off", "notify", "auto":
		return m
	}
	if get(setCheck, "0") == "1" {
		return "notify"
	}
	return "off"
}

// SaveMode speichert die Betriebsart samt alter Einstellung "nur pruefen"; aus verwirft das letzte Pruefergebnis
// (Einstellungsseite und Cluster).
func SaveMode(set func(k, v string) error, mode string) error {
	on := mode != "off"
	if err := set(SetMode, mode); err != nil {
		return err
	}
	if err := set(setCheck, map[bool]string{true: "1", false: "0"}[on]); err != nil {
		return err
	}
	if !on {
		return set(SetLatest, "")
	}
	return nil
}

// Channel: Kanal (Standard: preview, solange die laufende Version eine Vorab-Version ist).
func Channel(get Getter, running string) string {
	switch c := get(SetChannel, ""); c {
	case "stable", "preview":
		return c
	}
	if strings.Contains(strings.TrimPrefix(running, "v"), "-") {
		return "preview"
	}
	return "stable"
}

// Window: Zeitfenster fuer automatische Updates (Standard 03:00-05:00).
func Window(get Getter) string {
	w := get(SetWindow, "")
	if _, _, ok := parseWindow(w); ok {
		return w
	}
	return "03:00-05:00"
}

func parseWindow(w string) (from, to int, ok bool) {
	a, b, found := strings.Cut(strings.TrimSpace(w), "-")
	if !found {
		return 0, 0, false
	}
	pf, err1 := time.Parse("15:04", strings.TrimSpace(a))
	pt, err2 := time.Parse("15:04", strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return pf.Hour()*60 + pf.Minute(), pt.Hour()*60 + pt.Minute(), true
}

// ValidWindow: Eingabe "HH:MM-HH:MM".
func ValidWindow(w string) bool { _, _, ok := parseWindow(w); return ok }

// InWindow: ob now im Fenster liegt (auch ueber Mitternacht, z. B. 23:00-02:00).
func InWindow(w string, now time.Time) bool {
	from, to, ok := parseWindow(w)
	if !ok {
		return false
	}
	m := now.Hour()*60 + now.Minute()
	if from <= to {
		return m >= from && m < to
	}
	return m >= from || m < to
}

// Latest ist das gespeicherte Pruefergebnis (updates.latest; Felder wie bisher plus Kanal).
type Latest struct {
	Version   string    `json:"version"`
	URL       string    `json:"url,omitempty"` // Hinweise
	Channel   string    `json:"channel,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	Newer     bool      `json:"newer"`
	Error     string    `json:"error,omitempty"`
}

// CheckNow prueft den Kanal und speichert das Ergebnis.
func (u *Updater) CheckNow(ctx context.Context, get Getter, set func(key, value string) error) (*Manifest, error) {
	run, _, _ := Running(u.Current)
	ch := Channel(get, run)
	m, err := u.Check(ctx, ch)
	l := Latest{Channel: ch, CheckedAt: time.Now().UTC()}
	if err != nil {
		l.Error = err.Error()
	} else {
		l.Version, l.URL, l.Newer = m.Version, m.Notes, u.Newer(m)
	}
	b, _ := json.Marshal(l)
	_ = set(SetLatest, string(b))
	return m, err
}

// Loop prueft stuendlich (Betriebsart notify/auto) und installiert bei "auto" im Zeitfenster. Entwicklungsstaende
// (-dev) und fehlgeschlagene Versionen werden nie automatisch installiert.
func (u *Updater) Loop(ctx context.Context, get Getter, set func(key, value string) error, loc func() *time.Location, log *slog.Logger) {
	run := func() {
		mode := Mode(get)
		if mode == "off" {
			return
		}
		m, err := u.CheckNow(ctx, get, set)
		if err != nil {
			log.Debug("update check failed", "err", err)
			return
		}
		if !u.Newer(m) {
			return
		}
		log.Info("new node version available", "version", m.Version)
		st := u.Status()
		if mode != "auto" || st.Dev || containsStr(st.Bad, m.Version) || !InWindow(Window(get), time.Now().In(loc())) {
			return
		}
		log.Info("installing update", "version", m.Version)
		if err := u.Apply(ctx, m); err != nil {
			log.Warn("update failed", "version", m.Version, "err", err)
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
		run()
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Event ist eine Meldung des Selbst-Updates (fuer die Benachrichtigungen).
type Event struct {
	OK      bool
	Version string // neue bzw. fehlgeschlagene Version
	Other   string // vorige bzw. jetzt laufende Version
}

// Watch markiert die laufende Version nach HealthyAfter als gesund und meldet Erfolg bzw. einen Rueckfall beim
// Start (einmal). report darf nil sein.
func Watch(ctx context.Context, dataDir, current string, report func(Event)) {
	run, origin, img := Running(current)
	if st, err := LoadState(dataDir); err == nil && st.Notice != "" && !st.NoticeSent {
		if p := strings.Split(st.Notice, "|"); len(p) == 3 && report != nil {
			report(Event{Version: p[0], Other: p[1]})
		}
		st.NoticeSent = true
		_ = st.Save(dataDir)
	}
	if origin != "update" {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(HealthyAfter):
	}
	from, done, err := MarkHealthy(dataDir, run)
	if err == nil && done && report != nil {
		if from == "" {
			from = img
		}
		report(Event{OK: true, Version: run, Other: from})
	}
}
