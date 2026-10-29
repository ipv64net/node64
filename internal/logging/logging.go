// Package logging kapselt slog mit drei Zusaetzen, die der Node braucht:
//
//   - Log-Level zur Laufzeit umschaltbar, global und je Modul, mit
//     automatischem Zuruecksetzen nach einer einstellbaren Zeit.
//   - Ringpuffer der letzten Zeilen fuer die Anzeige im UI.
//   - Maskierung von Geheimnissen: Attribute, deren Name nach Passwort,
//     Token oder Schluessel aussieht, erscheinen nie im Klartext.
//
// Module loggen mit logger.With("module", "<name>"), dann greift das Level
// des Moduls.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const Masked = "***"

// Logger haelt den Zustand und liefert slog.Handler.
type Logger struct {
	mu          sync.RWMutex
	level       slog.Level
	defaultLvl  slog.Level
	resetAt     time.Time
	resetTimer  *time.Timer
	moduleLevel map[string]slog.Level
	ring        *Ring
	base        slog.Handler
	onChange    func()
}

// New erzeugt den Logger. format ist "text" oder "json".
func New(level, format string, out io.Writer) *Logger {
	l := &Logger{moduleLevel: map[string]slog.Level{}, ring: NewRing(2000)}
	l.defaultLvl = ParseLevel(level)
	l.level = l.defaultLvl
	if out == nil {
		out = os.Stdout
	}
	w := io.MultiWriter(out, l.ring)
	opts := &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: maskAttr}
	if format == "json" {
		l.base = slog.NewJSONHandler(w, opts)
	} else {
		l.base = slog.NewTextHandler(w, opts)
	}
	return l
}

// Handler liefert den slog.Handler, der Level und Module auswertet.
func (l *Logger) Handler() slog.Handler { return &handler{l: l, base: l.base} }

// Slog liefert einen fertigen *slog.Logger.
func (l *Logger) Slog() *slog.Logger { return slog.New(l.Handler()) }

// Record schreibt eine Zeile (Info) unabhaengig vom Log-Level, fuer ausdruecklich eingeschaltete Protokolle wie das
// API-Log. Geheimnisse werden wie sonst maskiert.
func (l *Logger) Record(ctx context.Context, msg string, attrs ...slog.Attr) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
	r.AddAttrs(attrs...)
	_ = l.base.Handle(ctx, r)
}

// Level ist das aktuelle globale Level.
func (l *Logger) Level() slog.Level {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
}

// ResetAt sagt, wann das Level automatisch zurueckgesetzt wird (Nullzeit = nie).
func (l *Logger) ResetAt() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.resetAt
}

// SetLevel setzt das globale Level. Mit d > 0 faellt es nach d wieder auf
// das Startlevel zurueck, damit Debug nicht versehentlich dauerhaft laeuft.
func (l *Logger) SetLevel(lvl slog.Level, d time.Duration) {
	l.mu.Lock()
	l.level = lvl
	if l.resetTimer != nil {
		l.resetTimer.Stop()
		l.resetTimer = nil
	}
	l.resetAt = time.Time{}
	if d > 0 && lvl != l.defaultLvl {
		l.resetAt = time.Now().Add(d)
		l.resetTimer = time.AfterFunc(d, func() {
			l.mu.Lock()
			l.level = l.defaultLvl
			l.resetAt = time.Time{}
			l.resetTimer = nil
			cb := l.onChange
			l.mu.Unlock()
			if cb != nil {
				cb()
			}
		})
	}
	cb := l.onChange
	l.mu.Unlock()
	if cb != nil {
		cb()
	}
}

// OnChange registriert einen Callback fuer Level-Aenderungen (z. B. um sie zu loggen).
func (l *Logger) OnChange(f func()) {
	l.mu.Lock()
	l.onChange = f
	l.mu.Unlock()
}

// SetModuleLevel setzt ein eigenes Level fuer ein Modul; nil-Level entfernt es.
func (l *Logger) SetModuleLevel(module string, lvl *slog.Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lvl == nil {
		delete(l.moduleLevel, module)
		return
	}
	l.moduleLevel[module] = *lvl
}

// ModuleLevels liefert eine Kopie der Modul-Level.
func (l *Logger) ModuleLevels() map[string]slog.Level {
	l.mu.RLock()
	defer l.mu.RUnlock()
	m := make(map[string]slog.Level, len(l.moduleLevel))
	for k, v := range l.moduleLevel {
		m[k] = v
	}
	return m
}

// Lines liefert die letzten n Logzeilen (aelteste zuerst).
func (l *Logger) Lines(n int) []string { return l.ring.Last(n) }

// Close stoppt Timer.
func (l *Logger) Close() {
	l.mu.Lock()
	if l.resetTimer != nil {
		l.resetTimer.Stop()
	}
	l.mu.Unlock()
}

func (l *Logger) effective(module string) slog.Level {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if module != "" {
		if lvl, ok := l.moduleLevel[module]; ok {
			return lvl
		}
	}
	return l.level
}

func (l *Logger) minLevel() slog.Level {
	l.mu.RLock()
	defer l.mu.RUnlock()
	min := l.level
	for _, v := range l.moduleLevel {
		if v < min {
			min = v
		}
	}
	return min
}

// handler filtert nach Level und Modul und reicht an den Basis-Handler weiter.
type handler struct {
	l      *Logger
	base   slog.Handler
	module string
}

func (h *handler) Enabled(_ context.Context, lvl slog.Level) bool {
	if h.module != "" {
		return lvl >= h.l.effective(h.module)
	}
	return lvl >= h.l.minLevel()
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	module := h.module
	if module == "" {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "module" {
				module = a.Value.String()
				return false
			}
			return true
		})
	}
	if r.Level < h.l.effective(module) {
		return nil
	}
	return h.base.Handle(ctx, r)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := &handler{l: h.l, base: h.base.WithAttrs(attrs), module: h.module}
	for _, a := range attrs {
		if a.Key == "module" {
			nh.module = a.Value.String()
		}
	}
	return nh
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{l: h.l, base: h.base.WithGroup(name), module: h.module}
}

// ParseLevel wandelt debug/info/warn/error in slog.Level um; unbekannt = info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// LevelName liefert debug/info/warn/error.
func LevelName(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug:
		return "debug"
	case l <= slog.LevelInfo:
		return "info"
	case l <= slog.LevelWarn:
		return "warn"
	default:
		return "error"
	}
}

// "passw" deckt password, passwd und passwort ab; "private" nur als Schluessel (private_key, privkey), ein
// Merkmal wie "private" (Adresse aus privatem Netz) ist kein Geheimnis. Mitgenutzt von internal/mcp.
var secretKeyParts = []string{"passw", "secret", "token", "apikey", "api_key", "authorization", "private_key", "privatekey", "privkey", "credential", "cookie"}

// IsSecretKey sagt, ob ein Attributname nach einem Geheimnis aussieht.
func IsSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, p := range secretKeyParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

func maskAttr(_ []string, a slog.Attr) slog.Attr {
	if IsSecretKey(a.Key) && a.Value.Kind() != slog.KindGroup {
		return slog.String(a.Key, Masked)
	}
	return a
}

// Ring ist ein Ringpuffer fuer Logzeilen und implementiert io.Writer.
type Ring struct {
	mu    sync.Mutex
	lines []string
	size  int
	pos   int
	full  bool
	rest  string
}

func NewRing(size int) *Ring { return &Ring{lines: make([]string, size), size: size} }

func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.rest + string(p)
	for {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			break
		}
		r.add(s[:i])
		s = s[i+1:]
	}
	r.rest = s
	return len(p), nil
}

func (r *Ring) add(line string) {
	r.lines[r.pos] = line
	r.pos = (r.pos + 1) % r.size
	if r.pos == 0 {
		r.full = true
	}
}

// Last liefert die letzten n Zeilen, aelteste zuerst.
func (r *Ring) Last(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var all []string
	if r.full {
		all = append(append([]string{}, r.lines[r.pos:]...), r.lines[:r.pos]...)
	} else {
		all = append([]string{}, r.lines[:r.pos]...)
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}
