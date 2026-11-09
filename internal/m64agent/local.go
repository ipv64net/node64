package m64agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Grenzen fuer eigene Skripte (local.d).
const (
	localMaxScripts   = 64   // hoechstens so viele Skripte je Runde
	localMaxParallel  = 4    // gleichzeitig laufende Skripte
	localMaxLines     = 1000 // Zeilen je Skript
	localMaxChecks    = 2000 // Dienste insgesamt
	localMaxMetrics   = 32   // Messwerte je Zeile
	localMaxNameLen   = 200
	localMaxTextLen   = 2000
	localMaxMetricLen = 100
)

// localHome ist HOME fuer eigene Skripte (Unix): unter systemd beschreibbar (StateDirectory=monitor64-agent), /root
// ist dort nur lesbar (ProtectHome=read-only) - Zugangsdateien wie /root/.my.cnf mit vollem Pfad angeben.
const localHome = "/var/lib/monitor64-agent"

// ParseLocal liest die Ausgabe eines Skripts im Format der CheckMK-"local checks":
//
//	<Status> <Name> <Metriken> <Text>
//
// Status 0..3 oder P (Zustand aus den Schwellen der Metriken; wertet der Agent selbst aus, auch Bereiche
// "warn_unten:warn_oben", und liefert dann 0..2). Name ohne Leerzeichen oder in doppelten Anfuehrungszeichen.
// Metriken "-" oder "name=wert;warn;crit;min;max|name2=wert2". Zeilen mit "<<<" (Abschnittskopf) werden
// uebersprungen. Liefert die Dienste und die Zahl unlesbarer Zeilen.
func ParseLocal(out []byte, script string) ([]m64proto.LocalCheck, int) {
	var checks []m64proto.LocalCheck
	bad := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), m64proto.LocalMaxBytes+1)
	lines := 0
	for sc.Scan() {
		lines++
		if lines > localMaxLines {
			bad++
			break
		}
		line := strings.TrimSpace(strings.ToValidUTF8(sc.Text(), "�"))
		if line == "" || strings.HasPrefix(line, "<<<") || strings.HasPrefix(line, "#") {
			continue
		}
		c, ok := parseLocalLine(line)
		if !ok {
			bad++
			continue
		}
		c.Script = script
		checks = append(checks, c)
	}
	return checks, bad
}

func parseLocalLine(line string) (m64proto.LocalCheck, bool) {
	var c m64proto.LocalCheck
	st, rest, ok := cutField(line)
	if !ok {
		return c, false
	}
	isP := false
	switch st {
	case "0", "1", "2", "3":
		c.State = int(st[0] - '0')
	case "P":
		isP = true
	default:
		return c, false
	}
	// Name: ohne Leerzeichen oder in Anfuehrungszeichen.
	rest = strings.TrimLeft(rest, " \t")
	if strings.HasPrefix(rest, `"`) {
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 {
			return c, false
		}
		c.Name = rest[1 : 1+end]
		rest = rest[2+end:]
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			return c, false
		}
	} else {
		c.Name, rest, ok = cutField(rest)
		if !ok {
			return c, false
		}
	}
	c.Name = cleanText(c.Name, localMaxNameLen)
	if c.Name == "" {
		return c, false
	}
	perf, text, ok := cutField(strings.TrimLeft(rest, " \t"))
	if !ok {
		// Ohne Text ist die Zeile gueltig, solange die Metriken stehen.
		perf, text = strings.TrimSpace(rest), ""
		if perf == "" {
			return c, false
		}
	}
	c.Text = cleanText(strings.TrimSpace(text), localMaxTextLen)
	var lows []localLow
	if perf != "-" {
		for i, m := range strings.Split(perf, "|") {
			if i >= localMaxMetrics {
				break
			}
			met, low, ok := parseMetric(m)
			if !ok {
				return c, false
			}
			c.Metrics = append(c.Metrics, met)
			lows = append(lows, low)
		}
	}
	if isP {
		c.State = evalP(c.Metrics, lows)
	}
	return c, true
}

// cutField trennt das erste durch Leerzeichen begrenzte Feld ab.
func cutField(s string) (string, string, bool) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i <= 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

// localLow sind die Untergrenzen eines Bereichs "unten:oben" (nur fuer die Auswertung von P).
type localLow struct{ warn, crit *float64 }

// parseMetric liest "name=wert;warn;crit;min;max"; warn/crit auch als Bereich "unten:oben".
func parseMetric(s string) (m64proto.Metric, localLow, bool) {
	var m m64proto.Metric
	var low localLow
	name, vals, ok := strings.Cut(s, "=")
	if !ok || name == "" || len(name) > localMaxMetricLen {
		return m, low, false
	}
	m.Name = cleanText(name, localMaxMetricLen)
	parts := strings.Split(vals, ";")
	if len(parts) > 5 {
		return m, low, false
	}
	v, ok := parseNum(parts[0])
	if !ok || v == nil {
		return m, low, false
	}
	m.Value = *v
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if i <= 2 && strings.Contains(p, ":") {
			lo, hi, _ := strings.Cut(p, ":")
			l, ok1 := parseNum(lo)
			h, ok2 := parseNum(hi)
			if !ok1 || !ok2 {
				return m, low, false
			}
			if i == 1 {
				low.warn, m.Warn = l, h
			} else {
				low.crit, m.Crit = l, h
			}
			continue
		}
		n, ok := parseNum(p)
		if !ok {
			return m, low, false
		}
		switch i {
		case 1:
			m.Warn = n
		case 2:
			m.Crit = n
		case 3:
			m.Min = n
		case 4:
			m.Max = n
		}
	}
	return m, low, true
}

// parseNum liest eine Zahl; leer = nil. Eine Einheit am Ende (ms, %, B ...) wird abgeschnitten.
func parseNum(s string) (*float64, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimRightFunc(s, func(r rune) bool { return unicode.IsLetter(r) || r == '%' || r == '/' })
	if s == "" {
		return nil, true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f != f || f > 1e300 || f < -1e300 {
		return nil, false
	}
	return &f, true
}

// evalP bestimmt den Zustand aus den Schwellen (wie CheckMK: ab warn bzw. crit nach oben, unter der Untergrenze
// nach unten). Ohne Schwellen OK.
func evalP(ms []m64proto.Metric, lows []localLow) int {
	st := 0
	for i, m := range ms {
		if m.Crit != nil && m.Value >= *m.Crit || lows[i].crit != nil && m.Value < *lows[i].crit {
			return 2
		}
		if m.Warn != nil && m.Value >= *m.Warn || lows[i].warn != nil && m.Value < *lows[i].warn {
			st = 1
		}
	}
	return st
}

// cleanText entfernt Steuerzeichen und kuerzt auf n Bytes (an einer Zeichengrenze).
func cleanText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// localRunner fuehrt die Skripte aus local.d aus. Die Skripte laufen im Hintergrund (je Skript hoechstens ein Lauf
// gleichzeitig, Zeitlimit LocalTimeoutMs); collect wartet nur kurz auf frisch gestartete Laeufe und liefert sonst
// das Ergebnis des letzten fertigen Laufs (wie CheckMK "cached"). Unterordner mit einer Zahl als Namen
// (z. B. local.d/300/) laufen wie bei CheckMK hoechstens alle N Sekunden.
type localRunner struct {
	dir    string
	base   context.Context // endet mit close (Skripte werden abgebrochen)
	cancel context.CancelFunc
	sem    chan struct{} // gleichzeitig laufende Skripte
	wg     sync.WaitGroup

	mu     sync.Mutex
	closed bool
	state  map[string]*localState // Anzeigename -> Stand
}

// localState ist der Stand eines Skripts.
type localState struct {
	path    string
	running bool
	done    chan struct{} // wird geschlossen, wenn der laufende Lauf endet
	have    bool          // mindestens ein Lauf fertig
	at      time.Time     // Ende des letzten Laufs
	checks  []m64proto.LocalCheck
	notes   []string
}

type localScript struct {
	path  string        // aufgeloester Pfad
	name  string        // Anzeige: Pfad relativ zu local.d
	every time.Duration // 0 = jede Runde
}

// localRound ist eine Abfrage: gefundene Skripte, Hinweise der Suche und die in dieser Runde gestarteten Laeufe.
type localRound struct {
	scripts []localScript
	notes   []string
	wait    []chan struct{}
}

func newLocalRunner(dir string) *localRunner {
	ctx, cancel := context.WithCancel(context.Background())
	return &localRunner{dir: dir, base: ctx, cancel: cancel, sem: make(chan struct{}, localMaxParallel),
		state: map[string]*localState{}}
}

// close bricht laufende Skripte ab und wartet auf sie.
func (r *localRunner) close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
}

// run startet die faelligen Skripte, wartet hoechstens bis ctx endet und haengt Dienste und Hinweise an den Report.
func (r *localRunner) run(ctx context.Context, rep *m64proto.Report) {
	r.finish(ctx, r.begin(), rep)
}

// begin sucht die Skripte und startet die faelligen im Hintergrund.
func (r *localRunner) begin() *localRound {
	scripts, notes := r.list()
	rd := &localRound{scripts: scripts, notes: notes}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]bool, len(scripts))
	for _, sc := range scripts {
		seen[sc.name] = true
		st := r.state[sc.name]
		if st == nil || st.path != sc.path {
			st = &localState{path: sc.path}
			r.state[sc.name] = st
		}
		due := !st.running && (sc.every == 0 || !st.have || now.Sub(st.at) >= sc.every)
		if !due || r.closed {
			continue
		}
		st.running = true
		st.done = make(chan struct{})
		rd.wait = append(rd.wait, st.done)
		r.wg.Add(1)
		go r.exec(sc, st)
	}
	for name := range r.state {
		if !seen[name] {
			delete(r.state, name) // Skript entfernt
		}
	}
	return rd
}

// exec fuehrt ein Skript im Hintergrund aus und merkt das Ergebnis.
func (r *localRunner) exec(sc localScript, st *localState) {
	defer r.wg.Done()
	var checks []m64proto.LocalCheck
	var notes []string
	select {
	case r.sem <- struct{}{}:
		checks, notes = r.runOne(r.base, sc)
		<-r.sem
	case <-r.base.Done():
		notes = []string{sc.name + ": not run (agent stopping)"}
	}
	r.mu.Lock()
	st.running, st.have, st.at = false, true, time.Now()
	st.checks, st.notes = checks, notes
	close(st.done)
	r.mu.Unlock()
}

// finish wartet auf die in dieser Runde gestarteten Laeufe (hoechstens bis ctx endet) und haengt die letzten
// Ergebnisse an den Report.
func (r *localRunner) finish(ctx context.Context, rd *localRound, rep *m64proto.Report) {
	for _, d := range rd.wait {
		select {
		case <-d:
		case <-ctx.Done():
		}
	}
	type result struct {
		checks []m64proto.LocalCheck
		notes  []string
	}
	results := make([]result, len(rd.scripts))
	r.mu.Lock()
	for i, sc := range rd.scripts {
		st := r.state[sc.name]
		switch {
		case st == nil || st.path != sc.path:
		case !st.have:
			results[i].notes = []string{sc.name + ": running for the first time - result follows with the next query"}
		default:
			results[i] = result{st.checks, st.notes}
		}
	}
	r.mu.Unlock()
	for _, n := range rd.notes {
		rep.Notes = append(rep.Notes, m64proto.SectionNote{Section: m64proto.SecLocal, Note: n})
	}
add:
	for _, res := range results {
		for _, c := range res.checks {
			if len(rep.Local) >= localMaxChecks {
				rep.Notes = append(rep.Notes, m64proto.SectionNote{Section: m64proto.SecLocal,
					Note: fmt.Sprintf("more than %d local checks - rest dropped", localMaxChecks)})
				break add
			}
			rep.Local = append(rep.Local, c)
		}
	}
	for _, res := range results {
		for _, n := range res.notes {
			rep.Notes = append(rep.Notes, m64proto.SectionNote{Section: m64proto.SecLocal, Note: n})
		}
	}
}

// list sucht die ausfuehrbaren Skripte und prueft Eigentuemer und Rechte (checkDir/checkScript, je Plattform:
// aufgeloester Pfad und alle Vorfahren gehoeren root und sind nicht fuer Gruppe/andere schreibbar).
func (r *localRunner) list() ([]localScript, []string) {
	var out []localScript
	var notes []string
	if fi, err := os.Stat(r.dir); err != nil || !fi.IsDir() {
		return nil, nil // kein local.d: keine eigenen Skripte
	}
	if err := checkDir(r.dir); err != nil {
		return nil, []string{"local.d ignored: " + err.Error()}
	}
	var walk func(dir, prefix string, every time.Duration)
	walk = func(dir, prefix string, every time.Duration) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			notes = append(notes, prefix+": "+err.Error())
			return
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
		for _, e := range ents {
			name := e.Name()
			if strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") {
				continue
			}
			p := filepath.Join(dir, name)
			rel := prefix + name
			if e.IsDir() {
				if every == 0 {
					if sec, err := strconv.Atoi(name); err == nil && sec > 0 && sec <= 86400 {
						if err := checkDir(p); err != nil {
							notes = append(notes, rel+" ignored: "+err.Error())
							continue
						}
						walk(p, rel+"/", time.Duration(sec)*time.Second)
					}
				}
				continue
			}
			if len(out) >= localMaxScripts {
				notes = append(notes, fmt.Sprintf("more than %d scripts - rest ignored", localMaxScripts))
				return
			}
			real, err := checkScript(p)
			if err != nil {
				notes = append(notes, rel+" ignored: "+err.Error())
				continue
			}
			out = append(out, localScript{path: real, name: rel, every: every})
		}
	}
	walk(r.dir, "", 0)
	return out, notes
}

// runOne fuehrt ein Skript mit Zeitlimit und Groessengrenze aus. Ausgefuehrt wird die geoeffnete und gepruefte
// Datei (Deskriptor), nicht erneut der Pfad - so kann sie zwischen Pruefung und Start niemand austauschen.
func (r *localRunner) runOne(ctx context.Context, sc localScript) ([]m64proto.LocalCheck, []string) {
	f, err := openScript(sc.path)
	if err != nil {
		return nil, []string{sc.name + " ignored: " + err.Error()}
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(ctx, m64proto.LocalTimeoutMs*time.Millisecond)
	defer cancel()
	cmd := scriptCmd(ctx, f, sc.path)
	cmd.Dir = filepath.Dir(sc.path)
	cmd.Env = localEnv()
	out := &limitBuf{max: m64proto.LocalMaxBytes}
	cmd.Stdout = out
	cmd.Stderr = nil
	cmd.Stdin = nil
	prepareCmd(cmd)
	cmd.WaitDelay = 2 * time.Second
	err = runCmd(cmd) // Windows: Job-Objekt (Zeitlimit beendet den ganzen Prozessbaum)
	var notes []string
	if ctx.Err() == context.DeadlineExceeded {
		notes = append(notes, fmt.Sprintf("%s: time limit of %d s exceeded - script stopped", sc.name, m64proto.LocalTimeoutMs/1000))
	} else if err != nil {
		if _, isExit := err.(*exec.ExitError); !isExit {
			notes = append(notes, sc.name+": "+err.Error())
		}
	}
	data := out.buf.Bytes()
	if out.over {
		// Die letzte, abgeschnittene Zeile verwerfen (sonst ein falscher Wert).
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		} else {
			data = nil
		}
		notes = append(notes, fmt.Sprintf("%s: output larger than %d bytes - truncated", sc.name, m64proto.LocalMaxBytes))
	}
	checks, bad := ParseLocal(data, sc.name)
	if bad > 0 {
		notes = append(notes, fmt.Sprintf("%s: %d unreadable lines", sc.name, bad))
	}
	return checks, notes
}

// limitBuf nimmt hoechstens max Bytes auf und verwirft den Rest (das Skript laeuft weiter, bis es endet).
type limitBuf struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *limitBuf) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.over = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.over = true
	}
	return len(p), nil
}
