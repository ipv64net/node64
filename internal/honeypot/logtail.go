package honeypot

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Dateien mitlesen (Log-Sensor, Plan Abschnitt 1b): ohne inotify, Abfrage alle LogPoll. Muster (filepath.Glob) werden
// bei jeder Abfrage neu aufgeloest (hoechstens LogMaxFiles Dateien). Beim ersten Oeffnen einer schon vorhandenen Datei
// geht es ans Ende (alte Zeilen werden nicht nachgelesen); Dateien, die spaeter erscheinen oder rotiert wurden, liest
// der Leser von vorn. Erkannt werden Rotation (andere Datei unter dem Pfad: die alte wird erst ausgelesen),
// Kuerzung (Groesse kleiner als die Leseposition) und verschwundene Dateien. Fehler (z. B. fehlende Rechte) stehen
// am Status der Datei; jede Abfrage versucht es erneut.

const (
	logReadBudget = 4 << 20  // hoechstens so viele Bytes je Datei und Abfrage (Rest bei der naechsten)
	logReadChunk  = 64 << 10 // Lesepuffer
	logFutureSkew = 5 * time.Minute
)

// logTailer liest die Dateien einer Einstellung.
type logTailer struct {
	log  *slog.Logger
	feed func(LogLine)
	now  func() time.Time

	mu      sync.Mutex // alles darunter; eine Abfrage laeuft ganz unter mu
	cfg     []LogFile
	files   map[string]*logTailFile
	order   []string
	missing []LogFileStatus // Eintraege ohne Datei, zu viele Dateien
	buf     []byte

	stopCh chan struct{}
	done   chan struct{}
}

// logTailFile ist eine gelesene Datei.
type logTailFile struct {
	path      string
	cfgFormat string // aus der Einstellung ("" = automatisch)
	format    string // verwendetes Format
	detected  bool   // Format steht fest (eingestellt oder an der ersten Zeile erkannt)
	f         *os.File
	id        os.FileInfo // zuletzt geoeffnete Datei (auch nach dem Schliessen, fuer Rotation/Wiederoeffnen)
	prevID    os.FileInfo // Datei vor der letzten Rotation (gleiche Datei unter neuem Namen nicht doppelt lesen)
	off       int64
	pend      []byte // angefangene letzte Zeile
	fromStart bool   // naechstes Oeffnen von vorn (Datei neu erschienen oder rotiert)
	err       string
	lines     int64
	last      time.Time
}

func newLogTailer(log *slog.Logger, feed func(LogLine), now func() time.Time) *logTailer {
	if log == nil {
		log = slog.Default()
	}
	return &logTailer{log: log, feed: feed, now: now, files: map[string]*logTailFile{}}
}

// setFiles setzt die Einstellung und fragt sofort einmal ab (vorhandene Dateien ans Ende).
func (t *logTailer) setFiles(files []LogFile) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fresh := map[string]bool{}
	old := map[string]bool{}
	for _, f := range t.cfg {
		old[f.Path] = true
	}
	for _, f := range files {
		if !old[f.Path] {
			fresh[f.Path] = true
		}
	}
	t.cfg = append([]LogFile(nil), files...)
	t.scanLocked(fresh)
	t.readAllLocked()
}

// start fragt im Hintergrund alle LogPoll ab.
func (t *logTailer) start() {
	t.stopCh, t.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(t.done)
		tk := time.NewTicker(LogPoll)
		defer tk.Stop()
		for {
			select {
			case <-t.stopCh:
				return
			case <-tk.C:
				t.poll()
			}
		}
	}()
}

// stop beendet die Abfrage und schliesst alle Dateien.
func (t *logTailer) stop() {
	if t.stopCh != nil {
		close(t.stopCh)
		<-t.done
		t.stopCh = nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tf := range t.files {
		tf.close()
	}
	t.files, t.order, t.missing = map[string]*logTailFile{}, nil, nil
}

// poll ist eine Abfrage: Muster aufloesen, alle Dateien lesen.
func (t *logTailer) poll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scanLocked(nil)
	t.readAllLocked()
}

func (t *logTailer) readAllLocked() {
	for _, p := range t.order {
		t.pollFileLocked(t.files[p])
	}
}

// status liefert den Zustand je Datei (in der Reihenfolge der Einstellung), danach Eintraege ohne Datei.
func (t *logTailer) status() []LogFileStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]LogFileStatus, 0, len(t.order)+len(t.missing))
	for _, p := range t.order {
		tf := t.files[p]
		out = append(out, LogFileStatus{Path: p, Format: tf.format, OK: tf.f != nil && tf.err == "", Error: tf.err, Lines: tf.lines, Last: tf.last})
	}
	return append(out, t.missing...)
}

// scanLocked loest die Eintraege auf. fresh nennt neu eingestellte Eintraege: deren vorhandene Dateien beginnen am
// Ende; Dateien, die bei einer spaeteren Abfrage dazukommen, von vorn.
func (t *logTailer) scanLocked(fresh map[string]bool) {
	seen := map[string]bool{}
	var order []string
	var missing []LogFileStatus
	full := false
	for _, lf := range t.cfg {
		paths := logExpand(lf.Path)
		if len(paths) == 0 {
			missing = append(missing, LogFileStatus{Path: lf.Path, Format: lf.Format, Error: "no matching file"})
			continue
		}
		for _, p := range paths {
			if seen[p] {
				continue
			}
			if len(order) >= LogMaxFiles {
				full = true
				break
			}
			seen[p] = true
			order = append(order, p)
			tf := t.files[p]
			if tf == nil {
				tf = &logTailFile{path: p, fromStart: !fresh[lf.Path]}
				t.files[p] = tf
			}
			if tf.cfgFormat != lf.Format || (tf.format == "" && !tf.detected) {
				tf.cfgFormat = lf.Format
				tf.format, tf.detected = lf.Format, lf.Format != ""
				if !tf.detected {
					tf.format = logDetectName(p)
				}
			}
		}
	}
	if full {
		missing = append(missing, LogFileStatus{Error: "too many files (max " + itoa(LogMaxFiles) + ")"})
	}
	for p, tf := range t.files {
		if !seen[p] {
			tf.close()
			delete(t.files, p)
		}
	}
	t.order, t.missing = order, missing
}

// logExpand loest ein Muster auf (ohne Sonderzeichen: der Pfad selbst, auch wenn er fehlt). Komprimierte Dateien
// (rotierte .gz usw.) werden nie gelesen.
func logExpand(p string) []string {
	if !strings.ContainsAny(p, "*?[") {
		return []string{p}
	}
	m, err := filepath.Glob(p)
	if err != nil {
		return nil
	}
	out := m[:0]
	for _, x := range m {
		switch strings.ToLower(filepath.Ext(x)) {
		case ".gz", ".bz2", ".xz", ".zst", ".zip", ".lz4":
			continue
		}
		out = append(out, x)
	}
	return out
}

// pollFileLocked liest, was seit der letzten Abfrage dazugekommen ist, und erkennt Rotation und Kuerzung.
func (t *logTailer) pollFileLocked(tf *logTailFile) {
	if tf.f != nil {
		t.readLocked(tf) // zuerst auslesen: bei Rotation steht der Rest noch in der alten Datei
	}
	fi, err := os.Stat(tf.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			tf.fromStart = true // erscheint sie wieder, ist sie neu
		}
		if tf.f != nil {
			return // verschoben/geloescht: die alte bleibt offen, bis eine neue erscheint
		}
		t.setErr(tf, logErrText(err))
		return
	}
	if fi.IsDir() {
		tf.close()
		t.setErr(tf, "is a directory")
		return
	}
	if !fi.Mode().IsRegular() { // FIFO, Geraet, Socket: Open koennte blockieren (unter t.mu) bzw. nie enden
		tf.close()
		t.setErr(tf, "not a regular file")
		return
	}
	if tf.f != nil {
		if os.SameFile(fi, tf.id) {
			if fi.Size() < tf.off { // gekuerzt (copytruncate): von vorn
				t.rewindLocked(tf)
				t.readLocked(tf)
			}
			return
		}
		tf.prevID = tf.id // rotiert: die alte ist ausgelesen, die neue von vorn
		tf.close()
		tf.fromStart = true
	}
	t.openLocked(tf)
	if tf.f != nil {
		t.readLocked(tf)
	}
}

// openLocked oeffnet die Datei und waehlt die Leseposition.
func (t *logTailer) openLocked(tf *logTailFile) {
	f, err := os.Open(tf.path)
	if err != nil {
		t.setErr(tf, logErrText(err))
		return
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		t.setErr(tf, logErrText(err))
		return
	}
	same := tf.id != nil && os.SameFile(fi, tf.id)
	rotated := tf.id != nil && !same // auch, wenn die alte gerade nicht offen war
	if rotated {
		tf.prevID = tf.id
	}
	switch {
	case same && fi.Size() >= tf.off: // dieselbe Datei wieder offen (z. B. nach Lesefehler): weiter wie zuvor
	case same: // inzwischen gekuerzt
		tf.off, tf.pend = 0, tf.pend[:0]
	case (tf.fromStart || rotated) && !t.knownLocked(tf, fi): // neu erschienen oder rotiert
		tf.off, tf.pend = 0, tf.pend[:0]
	default: // schon vorhanden: alte Zeilen nicht nachlesen
		tf.off, tf.pend = fi.Size(), tf.pend[:0]
	}
	if _, err := f.Seek(tf.off, io.SeekStart); err != nil {
		f.Close()
		t.setErr(tf, logErrText(err))
		return
	}
	tf.f, tf.id, tf.fromStart = f, fi, false
	t.setErr(tf, "")
}

// knownLocked meldet, ob fi schon unter einem anderen Pfad gelesen wird oder wurde (rotierte Datei, die ein Muster
// unter neuem Namen findet): dann nicht noch einmal von vorn lesen.
func (t *logTailer) knownLocked(tf *logTailFile, fi os.FileInfo) bool {
	for _, o := range t.files {
		if o == tf {
			continue
		}
		if (o.id != nil && os.SameFile(o.id, fi)) || (o.prevID != nil && os.SameFile(o.prevID, fi)) {
			return true
		}
	}
	return false
}

func (t *logTailer) rewindLocked(tf *logTailFile) {
	tf.off, tf.pend = 0, tf.pend[:0]
	if _, err := tf.f.Seek(0, io.SeekStart); err != nil {
		tf.close()
		t.setErr(tf, logErrText(err))
	}
}

// readLocked liest bis zum Ende (hoechstens logReadBudget) und gibt jede vollstaendige Zeile weiter.
func (t *logTailer) readLocked(tf *logTailFile) {
	if t.buf == nil {
		t.buf = make([]byte, logReadChunk)
	}
	for budget := logReadBudget; budget > 0 && tf.f != nil; {
		n, err := tf.f.Read(t.buf)
		if n > 0 {
			tf.off += int64(n)
			budget -= n
			t.splitLocked(tf, t.buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				tf.close()
				t.setErr(tf, logErrText(err))
			}
			return
		}
		if n == 0 {
			return
		}
	}
}

// splitLocked zerlegt b in Zeilen; die angefangene letzte bleibt in pend. Zeilen ueber LogMaxLine werden gekuerzt.
func (t *logTailer) splitLocked(tf *logTailFile, b []byte) {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		part := b
		if i >= 0 {
			part = b[:i]
		}
		if room := LogMaxLine - len(tf.pend); len(part) > room {
			part = part[:max(room, 0)]
		}
		tf.pend = append(tf.pend, part...)
		if i < 0 {
			return
		}
		t.emitLocked(tf, tf.pend)
		tf.pend = tf.pend[:0]
		b = b[i+1:]
	}
}

func (t *logTailer) emitLocked(tf *logTailFile, raw []byte) {
	raw = bytes.TrimRight(raw, "\r")
	if len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	s := string(raw)
	if !tf.detected { // Format an der ersten Zeile erkennen bzw. verfeinern
		tf.detected = true
		if c := logDetectContent(s); c != "" && (tf.format == "" || tf.format == "nginx" && c == "caddy") {
			tf.format = c
		}
	}
	now := t.now()
	tf.lines++
	tf.last = now
	if t.feed != nil {
		t.feed(logFileLine(tf.format, tf.path, s, now))
	}
}

func (tf *logTailFile) close() {
	if tf.f != nil {
		tf.f.Close()
		tf.f = nil
	}
}

func (t *logTailer) setErr(tf *logTailFile, msg string) {
	if msg == tf.err {
		return
	}
	if msg != "" {
		t.log.Warn("honeypot log file not readable", "path", tf.path, "err", msg)
	}
	tf.err = msg
}

// logErrText kuerzt Dateifehler auf die Ursache (der Pfad steht schon am Status).
func logErrText(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, fs.ErrNotExist):
		return "file not found"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// Zeilen zerlegen.

// logFileLine macht aus einer Dateizeile eine LogLine. Zeiten ohne Zeitzone (klassisches Syslog, die meisten
// Anwendungs-Logs) gelten als Lesezeit, weil der Container oft eine andere Zone hat als der Host; Zeiten mit Zone
// werden uebernommen (Zukunft wird auf jetzt gekappt).
func logFileLine(format, file, s string, now time.Time) LogLine {
	now = now.UTC()
	l := LogLine{Time: now, Origin: SrcLog, File: file, Format: format, Message: s}
	switch format {
	case "syslog", "proxmox":
		if t, host, prog, msg, ok := logParseSyslogFile(s, now); ok {
			l.Time, l.Host, l.Program, l.Message = t, host, prog, msg
		}
	case "nginx", "apache":
		if t, ok := logWebTime(s, now); ok {
			l.Time = t
		}
	}
	return l
}

// logParseSyslogFile zerlegt "Oct 20 12:00:01 host prog[123]: msg" und "2026-10-20T12:00:01.123+02:00 host prog: msg".
func logParseSyslogFile(s string, now time.Time) (t time.Time, host, prog, msg string, ok bool) {
	var rest string
	switch {
	case len(s) > 16 && s[3] == ' ' && s[6] == ' ' && s[9] == ':' && s[12] == ':' && s[15] == ' ' && logIsMonth(s[:3]):
		t, rest = now, s[16:] // ohne Jahr und Zone: Lesezeit
	case len(s) > 20 && s[4] == '-' && s[7] == '-' && s[10] == 'T':
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			return
		}
		pt, err := time.Parse(time.RFC3339Nano, s[:i])
		if err != nil {
			return
		}
		t, rest = logClampTime(pt, now), s[i+1:]
	default:
		return
	}
	i := strings.IndexByte(rest, ' ')
	if i <= 0 {
		return
	}
	host, rest = rest[:i], rest[i+1:]
	prog, msg = logSplitTag(rest)
	return t, host, prog, msg, true
}

// logSplitTag trennt "prog[123]: msg" in Programm (ohne PID) und Nachricht; ohne Tag ist alles Nachricht.
func logSplitTag(s string) (prog, msg string) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i > 64 || strings.IndexByte(s[:i], ' ') >= 0 {
		return "", s
	}
	prog = s[:i]
	if j := strings.IndexByte(prog, '['); j > 0 {
		prog = prog[:j]
	} else if j == 0 {
		return "", s
	}
	return prog, strings.TrimPrefix(s[i+1:], " ")
}

func logIsMonth(m string) bool {
	switch m {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	}
	return false
}

func logClampTime(t, now time.Time) time.Time {
	if t.After(now.Add(logFutureSkew)) {
		return now
	}
	return t.UTC()
}

// logWebTime liest die Zeit aus "[20/Oct/2026:12:00:01 +0200]" (Apache/nginx; Proxmox schreibt den Monat als Zahl).
func logWebTime(s string, now time.Time) (time.Time, bool) {
	i := strings.IndexByte(s, '[')
	if i < 0 || i > 300 {
		return time.Time{}, false
	}
	j := strings.IndexByte(s[i:], ']')
	if j < 0 {
		return time.Time{}, false
	}
	v := s[i+1 : i+j]
	for _, layout := range []string{"02/Jan/2006:15:04:05 -0700", "02/01/2006:15:04:05 -0700"} {
		if t, err := time.Parse(layout, v); err == nil {
			return logClampTime(t, now), true
		}
	}
	return time.Time{}, false
}

// Format erkennen.

var logSyslogNames = map[string]bool{
	"auth.log": true, "secure": true, "mail.log": true, "maillog": true, "syslog": true, "messages": true,
	"daemon.log": true, "user.log": true, "kern.log": true, "mail.err": true, "mail.warn": true, "mail.info": true,
}

// logDetectName raet das Format am Dateinamen ("" = unbekannt, dann entscheidet die erste Zeile).
func logDetectName(p string) string {
	lp := strings.ToLower(filepath.ToSlash(p))
	base := path.Base(lp)
	switch {
	case base == "nextcloud.log":
		return "nextcloud"
	case strings.Contains(base, "home-assistant"):
		return "homeassistant"
	case strings.Contains(lp, "vaultwarden") || strings.Contains(lp, "bitwarden"):
		return "vaultwarden"
	case strings.Contains(base, "access") && strings.Contains(lp, "caddy"):
		return "caddy"
	case strings.Contains(base, "access") && strings.Contains(base, ".log"):
		return "nginx" // combined; deckt Apache combined mit ab (JSON wird an der ersten Zeile zu caddy)
	case base == "gitea.log" || base == "forgejo.log" || strings.Contains(lp, "/gitea/") || strings.Contains(lp, "/forgejo/"):
		return "gitea"
	case strings.Contains(lp, "caddy"):
		return "caddy"
	case logSyslogNames[base]:
		return "syslog"
	case strings.Contains(lp, "proxmox") || strings.Contains(lp, "/pve"):
		return "proxmox" // Syslog-Format
	}
	return ""
}

// logDetectContent erkennt das Format an einer Zeile ("" = unbekannt).
func logDetectContent(s string) string {
	if strings.HasPrefix(s, "{") {
		switch {
		case strings.Contains(s, `"remoteAddr"`):
			return "nextcloud"
		case strings.Contains(s, `"remote_ip"`) || strings.Contains(s, `"request"`):
			return "caddy"
		}
		return ""
	}
	if _, _, _, _, ok := logParseSyslogFile(s, time.Time{}); ok {
		return "syslog"
	}
	switch {
	case strings.HasPrefix(s, "[") && (strings.Contains(s, "][vaultwarden") || strings.Contains(s, "][bitwarden_rs")):
		return "vaultwarden"
	case len(s) > 20 && s[4] == '/' && s[7] == '/' && s[10] == ' ' && strings.Contains(s, ".go:"):
		return "gitea"
	case len(s) > 23 && s[4] == '-' && s[7] == '-' && s[10] == ' ' && (strings.Contains(s, "(MainThread)") || strings.Contains(s, "[homeassistant")):
		return "homeassistant"
	}
	if i := strings.IndexByte(s, ' '); i > 0 && strings.Contains(s, `] "`) {
		if _, err := netip.ParseAddr(s[:i]); err == nil {
			return "nginx"
		}
	}
	return ""
}
