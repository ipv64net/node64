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

// localRunner fuehrt die Skripte aus local.d aus. Unterordner mit einer Zahl als Namen (z. B. local.d/300/)
// laufen wie bei CheckMK hoechstens alle N Sekunden; dazwischen liefert der Agent den letzten Stand.
type localRunner struct {
	dir string

	mu    sync.Mutex
	cache map[string]localCached // Pfad -> letztes Ergebnis (nur Unterordner mit Intervall)
}

type localCached struct {
	at     time.Time
	checks []m64proto.LocalCheck
	notes  []string
}

type localScript struct {
	path  string
	name  string        // Anzeige: Pfad relativ zu local.d
	every time.Duration // 0 = jede Runde
}

// run fuehrt alle Skripte aus und haengt Dienste und Hinweise an den Report.
func (r *localRunner) run(ctx context.Context, rep *m64proto.Report) {
	scripts, notes := r.list()
	type result struct {
		checks []m64proto.LocalCheck
		notes  []string
	}
	results := make([]result, len(scripts))
	sem := make(chan struct{}, localMaxParallel)
	var wg sync.WaitGroup
	now := time.Now()
	for i, sc := range scripts {
		if sc.every > 0 {
			r.mu.Lock()
			c, ok := r.cache[sc.path]
			r.mu.Unlock()
			if ok && now.Sub(c.at) < sc.every {
				results[i] = result{c.checks, c.notes}
				continue
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i].notes = []string{sc.name + ": not run (time limit of the request)"}
				return
			}
			defer func() { <-sem }()
			checks, n := r.runOne(ctx, sc)
			results[i] = result{checks, n}
			if sc.every > 0 {
				r.mu.Lock()
				if r.cache == nil {
					r.cache = map[string]localCached{}
				}
				r.cache[sc.path] = localCached{at: time.Now(), checks: checks, notes: n}
				r.mu.Unlock()
			}
		}()
	}
	wg.Wait()
	for _, n := range notes {
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

// list sucht die ausfuehrbaren Skripte und prueft Eigentuemer und Rechte (checkScript, je Plattform).
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
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				notes = append(notes, rel+" ignored: "+err.Error())
				continue
			}
			if err := checkScript(real); err != nil {
				notes = append(notes, rel+" ignored: "+err.Error())
				continue
			}
			out = append(out, localScript{path: real, name: rel, every: every})
		}
	}
	walk(r.dir, "", 0)
	return out, notes
}

// runOne fuehrt ein Skript mit Zeitlimit und Groessengrenze aus.
func (r *localRunner) runOne(ctx context.Context, sc localScript) ([]m64proto.LocalCheck, []string) {
	ctx, cancel := context.WithTimeout(ctx, m64proto.LocalTimeoutMs*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, sc.path)
	cmd.Dir = filepath.Dir(sc.path)
	cmd.Env = localEnv()
	out := &limitBuf{max: m64proto.LocalMaxBytes}
	cmd.Stdout = out
	cmd.Stderr = nil
	cmd.Stdin = nil
	prepareCmd(cmd)
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	var notes []string
	if ctx.Err() == context.DeadlineExceeded {
		notes = append(notes, sc.name+": time limit exceeded")
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
