package honeypot

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SyslogServer nimmt Syslog per UDP und TCP auf einem Port an (RFC 3164 und RFC 5424, TCP mit Zeilenende oder
// Octet-Counting) und gibt jede Nachricht als LogLine (Origin SrcSyslog) an feed. Absender ausserhalb von allow werden
// verworfen und gezaehlt (leeres allow = private Netze und localhost).
//
// Verhalten:
//   - UDP und TCP auf allen Adressen (IPv4 und IPv6) desselben Ports. Ein Protokoll, das nicht geht (Port belegt, keine
//     Rechte), steht in Status().Error; das andere laeuft weiter. Ports unter 1024 (514) brauchen die Faehigkeit
//     cap_net_bind_service (im Image vorhanden).
//   - Absenderpruefung vor dem Parsen; TCP-Verbindungen fremder Absender werden sofort geschlossen.
//   - TCP: Rahmen je Nachricht automatisch erkannt (RFC 6587): beginnt sie mit "<Ziffern> " = Octet-Counting, sonst bis
//     LF bzw. NUL. Hoechstens SyslogMaxConns Verbindungen gleichzeitig, SyslogIdleTimeout ohne Daten, Nachrichten ueber
//     SyslogMaxMsg werden gekuerzt; ein unsinniger Octet-Count schliesst die Verbindung.
//   - feed wird aus den Lese-Goroutinen aufgerufen (UDP eine, TCP eine je Verbindung) und muss schnell zurueckkehren.
//   - ctx gilt nur fuer das Oeffnen der Ports; beendet wird ausschliesslich mit Stop.
type SyslogServer struct {
	log   *slog.Logger
	port  int
	allow []netip.Prefix
	feed  func(LogLine)

	maxConns int           // gleichzeitige TCP-Verbindungen (Tests setzen kleiner)
	idle     time.Duration // TCP ohne Daten

	mu      sync.Mutex
	running bool
	udp     *net.UDPConn
	tcp     net.Listener
	conns   map[net.Conn]struct{}
	err     string
	noted   map[netip.Addr]struct{} // abgewiesene Absender, schon im Log (begrenzt)

	messages atomic.Int64
	denied   atomic.Int64
	wg       sync.WaitGroup
}

const (
	syslogStopWait = 3 * time.Second
	syslogMaxFrame = 64 << 10 // groesster Octet-Count, der noch gelesen (und gekuerzt) wird; darueber = kaputt
	syslogReadBuf  = 16 << 10
	syslogMaxNoted = 32 // abgewiesene Absender, die einmal im Log erscheinen
)

// syslogDefaultAllow sind die Absender bei leerem allow: private Netze (RFC 1918, fc00::/7), Link-Local (fe80::/10),
// CGNAT (100.64.0.0/10) und localhost.
var syslogDefaultAllow = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// NewSyslogServer legt den Empfaenger an (noch nicht offen).
func NewSyslogServer(log *slog.Logger, port int, allow []netip.Prefix, feed func(LogLine)) *SyslogServer {
	if log == nil {
		log = slog.Default()
	}
	var list []netip.Prefix
	for _, p := range allow {
		if !p.IsValid() {
			continue
		}
		// ::ffff:a.b.c.d/n als IPv4-Netz behandeln (Absender werden ohne ::ffff: verglichen)
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		list = append(list, p.Masked())
	}
	if len(list) == 0 {
		list = syslogDefaultAllow
	}
	return &SyslogServer{log: log.With("module", Name), port: port, allow: list, feed: feed,
		maxConns: SyslogMaxConns, idle: SyslogIdleTimeout, conns: map[net.Conn]struct{}{}, noted: map[netip.Addr]struct{}{}}
}

// Start oeffnet UDP und TCP. Ein Fehler steht danach auch in Status().Error. Geht nur eines der beiden Protokolle,
// laeuft das andere weiter (der Fehler wird trotzdem geliefert, Stop ist noetig). Laeuft der Empfaenger schon, passiert
// nichts.
func (s *SyslogServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}
	s.err = ""
	if s.port < 1 || s.port > 65535 {
		s.err = "invalid port"
		return errors.New(s.err)
	}
	addr := ":" + strconv.Itoa(s.port)
	var lc net.ListenConfig
	var msgs []string
	if pc, err := lc.ListenPacket(ctx, "udp", addr); err != nil {
		msgs = append(msgs, "udp: "+sensorListenErr(err))
	} else if uc, ok := pc.(*net.UDPConn); !ok {
		_ = pc.Close()
		msgs = append(msgs, "udp: unexpected socket")
	} else {
		s.udp = uc
	}
	if ln, err := lc.Listen(ctx, "tcp", addr); err != nil {
		msgs = append(msgs, "tcp: "+sensorListenErr(err))
	} else {
		s.tcp = ln
	}
	s.err = strings.Join(msgs, "; ")
	if s.udp != nil || s.tcp != nil {
		s.running = true
	}
	if s.udp != nil {
		s.wg.Add(1)
		go s.serveUDP(s.udp)
	}
	if s.tcp != nil {
		s.wg.Add(1)
		go s.serveTCP(s.tcp)
	}
	if s.err != "" {
		s.log.Warn("syslog receiver not fully open", "port", s.port, "err", s.err)
		return errors.New(s.err)
	}
	s.log.Info("syslog receiver open", "port", s.port)
	return nil
}

// Stop schliesst alles und wartet auf die Verbindungen (hoechstens syslogStopWait).
func (s *SyslogServer) Stop() {
	s.mu.Lock()
	wasRunning := s.running
	s.running = false
	u, t := s.udp, s.tcp
	s.udp, s.tcp, s.err = nil, nil, ""
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if u != nil {
		_ = u.Close()
	}
	if t != nil {
		_ = t.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(syslogStopWait):
		s.log.Warn("syslog receiver did not end in time")
	}
	if wasRunning {
		s.log.Info("syslog receiver closed", "port", s.port)
	}
}

// Status liefert den Zustand.
func (s *SyslogServer) Status() SyslogStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SyslogStatus{Port: s.port, UDP: s.udp != nil, TCP: s.tcp != nil, Error: s.err,
		Messages: s.messages.Load(), Denied: s.denied.Load()}
}

// allowed prueft den Absender (ohne ::ffff: und Zone).
func (s *SyslogServer) allowed(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range s.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// deny zaehlt einen abgewiesenen Absender und schreibt ihn einmal ins Log (Hinweis auf fehlende Freigabe).
func (s *SyslogServer) deny(from netip.Addr, proto string) {
	s.denied.Add(1)
	s.mu.Lock()
	_, seen := s.noted[from]
	if !seen && len(s.noted) < syslogMaxNoted {
		s.noted[from] = struct{}{}
	} else {
		seen = true
	}
	s.mu.Unlock()
	if !seen {
		s.log.Info("syslog sender not allowed", "from", from, "proto", proto)
	}
}

// deliver zerlegt eine Nachricht und gibt sie weiter. Ein Fehler in feed (Panik einer Regel) beendet den Empfaenger
// nicht.
func (s *SyslogServer) deliver(msg []byte, from netip.Addr, file string) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("syslog message handling failed", "err", r)
		}
	}()
	l := ParseSyslog(msg, from, time.Now())
	l.File = file
	s.messages.Add(1)
	if s.feed != nil {
		s.feed(l)
	}
}

func (s *SyslogServer) serveUDP(uc *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 64<<10)
	var lastFrom netip.Addr
	var file string
	for {
		n, ap, err := uc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || !s.isOpen(uc) {
				return
			}
			time.Sleep(10 * time.Millisecond) // voruebergehend (z. B. ICMP-Fehler unter Windows)
			continue
		}
		from := ap.Addr().Unmap().WithZone("")
		if !s.allowed(from) {
			s.deny(from, "udp")
			continue
		}
		msg := buf[:n]
		if len(msg) > SyslogMaxMsg {
			msg = msg[:SyslogMaxMsg]
		}
		if msg = syslogTrim(msg); len(msg) == 0 {
			continue
		}
		if from != lastFrom || file == "" {
			lastFrom, file = from, "udp://"+from.String()
		}
		s.deliver(msg, from, file)
	}
}

func (s *SyslogServer) isOpen(uc *net.UDPConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp == uc
}

func (s *SyslogServer) serveTCP(ln net.Listener) {
	defer s.wg.Done()
	delay := 5 * time.Millisecond
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.tcp != ln
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(delay) // voruebergehend (z. B. EMFILE)
			delay = min(2*delay, time.Second)
			continue
		}
		delay = 5 * time.Millisecond
		from, _ := sensorAddr(c.RemoteAddr())
		from = from.WithZone("")
		if !s.allowed(from) {
			_ = c.Close()
			s.deny(from, "tcp")
			continue
		}
		s.mu.Lock()
		if s.tcp != ln || len(s.conns) >= s.maxConns {
			full := s.tcp == ln
			s.mu.Unlock()
			_ = c.Close()
			if full {
				s.log.Debug("syslog connection refused, limit reached", "from", from)
			}
			continue
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handleConn(c, from)
	}
}

// handleConn liest Nachrichten einer TCP-Verbindung bis Ende, Zeitlimit oder kaputtem Rahmen.
func (s *SyslogServer) handleConn(c net.Conn, from netip.Addr) {
	defer s.wg.Done()
	defer func() {
		_ = c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	r := bufio.NewReaderSize(c, syslogReadBuf)
	buf := make([]byte, 0, SyslogMaxMsg)
	file := "tcp://" + from.String()
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.idle))
		msg, err := syslogReadFrame(r, buf)
		if msg = syslogTrim(msg); len(msg) > 0 {
			s.deliver(msg, from, file)
		}
		if err != nil {
			if errors.Is(err, errSyslogFrame) {
				s.log.Debug("syslog connection closed, bad frame", "from", from)
			}
			return
		}
	}
}

var errSyslogFrame = errors.New("bad octet count")

// syslogReadFrame liest die naechste Nachricht (RFC 6587): Octet-Counting ("<Laenge> <Nachricht>") oder bis LF/NUL.
// Liefert hoechstens SyslogMaxMsg Bytes (Rest verworfen) in buf. Bei Fehler kann die Nachricht trotzdem Daten enthalten
// (letzte Zeile ohne Zeilenende).
func syslogReadFrame(r *bufio.Reader, buf []byte) ([]byte, error) {
	buf = buf[:0]
	// leere Trenner zwischen Nachrichten ueberspringen
	for {
		p, err := r.Peek(1)
		if err != nil {
			return buf, err
		}
		if c := p[0]; c != '\n' && c != '\r' && c != 0 && c != ' ' && c != '\t' {
			if c < '1' || c > '9' {
				return syslogReadLine(r, buf)
			}
			break
		}
		_, _ = r.Discard(1)
	}
	// Ziffern am Anfang: Octet-Count, wenn ein Leerzeichen folgt
	n, digits := 0, 0
	for {
		p, err := r.Peek(digits + 1)
		if err != nil {
			return syslogReadLine(r, buf) // Ende ohne Leerzeichen: als Zeile nehmen
		}
		c := p[digits]
		if c == ' ' {
			break
		}
		if c < '0' || c > '9' {
			return syslogReadLine(r, buf) // z. B. "2024-10-11T..." ohne PRI
		}
		digits++
		if digits > 6 {
			return buf, errSyslogFrame
		}
		n = n*10 + int(c-'0')
	}
	if n > syslogMaxFrame {
		return buf, errSyslogFrame
	}
	_, _ = r.Discard(digits + 1)
	keep := min(n, SyslogMaxMsg)
	buf = buf[:keep]
	if m, err := io.ReadFull(r, buf); err != nil {
		return buf[:m], err
	}
	if rest := n - keep; rest > 0 {
		if _, err := r.Discard(rest); err != nil {
			return buf, err
		}
	}
	return buf, nil
}

// syslogReadLine liest bis LF oder NUL (Trenner nicht enthalten); zu lange Zeilen werden gekuerzt.
func syslogReadLine(r *bufio.Reader, buf []byte) ([]byte, error) {
	for {
		if r.Buffered() == 0 {
			if _, err := r.Peek(1); err != nil {
				return buf, err
			}
		}
		p, _ := r.Peek(r.Buffered())
		i := bytes.IndexAny(p, "\n\x00")
		n := len(p)
		if i >= 0 {
			n = i
		}
		if room := SyslogMaxMsg - len(buf); room > 0 {
			buf = append(buf, p[:min(n, room)]...)
		}
		if i >= 0 {
			_, _ = r.Discard(i + 1)
			return buf, nil
		}
		_, _ = r.Discard(n)
	}
}

var syslogBOM = []byte{0xEF, 0xBB, 0xBF}

// syslogTrim entfernt Leerraum, NUL und CR/LF an beiden Enden und eine BOM am Anfang.
func syslogTrim(b []byte) []byte {
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0 }
	for len(b) > 0 && isSpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	for len(b) > 0 && isSpace(b[0]) {
		b = b[1:]
	}
	b = bytes.TrimPrefix(b, syslogBOM)
	return b
}

// ParseSyslog zerlegt eine Nachricht (ohne Octet-Count/Zeilenende). from ist der Absender, now die Empfangszeit.
//
// Erkannt werden RFC 5424 ("<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG") und RFC 3164 ("<PRI>Mmm dd hh:mm:ss
// host tag[pid]: msg", auch ohne PRI, ohne Zeit oder ohne Host, auch mit RFC-3339-Zeit statt "Mmm dd"). Key=Value-
// Nachrichten (FortiGate, Sophos) bleiben als ganze Message erhalten. Die Zeit aus der Nachricht gilt, wenn sie
// hoechstens einen Tag von now abweicht, sonst now. File setzt der Empfaenger.
func ParseSyslog(raw []byte, from netip.Addr, now time.Time) LogLine {
	if now.IsZero() {
		now = time.Now()
	}
	l := LogLine{Time: now.UTC(), Origin: SrcSyslog, Format: "syslog"}
	b := syslogTrim(raw)
	if len(b) > SyslogMaxMsg {
		b = b[:SyslogMaxMsg]
	}
	if n := syslogPRI(b); n > 0 {
		b = b[n:]
	}
	var t time.Time
	if n := syslog5424Version(b); n > 0 {
		t = syslogParse5424(&l, b[n:])
	} else {
		t = syslogParse3164(&l, b, now)
	}
	if !t.IsZero() {
		if d := t.Sub(now); d <= 24*time.Hour && d >= -24*time.Hour {
			l.Time = t.UTC()
		}
	}
	return l
}

// syslogPRI liefert die Laenge von "<PRI>" (0 = keine gueltige PRI).
func syslogPRI(b []byte) int {
	if len(b) < 3 || b[0] != '<' {
		return 0
	}
	v := 0
	for i := 1; i < len(b) && i <= 4; i++ {
		c := b[i]
		if c == '>' {
			if i == 1 || v > 191 {
				return 0
			}
			return i + 1
		}
		if c < '0' || c > '9' {
			return 0
		}
		v = v*10 + int(c-'0')
	}
	return 0
}

// syslog5424Version liefert die Laenge von "VERSION " (0 = kein RFC 5424). Danach muss ein Zeitstempel oder "-" folgen.
func syslog5424Version(b []byte) int {
	i := 0
	for i < len(b) && i < 2 && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == 0 || b[0] == '0' || i >= len(b) || b[i] != ' ' {
		return 0
	}
	r := b[i+1:]
	if len(r) >= 2 && r[0] == '-' && r[1] == ' ' {
		return i + 1
	}
	if len(r) >= 11 && syslogDigits(r[:4]) && r[4] == '-' && r[7] == '-' && r[10] == 'T' {
		return i + 1
	}
	return 0
}

func syslogDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(b) > 0
}

// syslogField trennt das erste durch ein Leerzeichen begrenzte Feld ab.
func syslogField(b []byte) (field, rest []byte) {
	if i := bytes.IndexByte(b, ' '); i >= 0 {
		return b[:i], b[i+1:]
	}
	return b, nil
}

// syslogNil liefert "" fuer das RFC-5424-Nichts "-".
func syslogNil(b []byte) string {
	if len(b) == 1 && b[0] == '-' {
		return ""
	}
	return string(b)
}

// syslogParse5424 fuellt Host, Program und Message; liefert die Zeit der Nachricht (Null = keine).
func syslogParse5424(l *LogLine, b []byte) time.Time {
	ts, b := syslogField(b)
	host, b := syslogField(b)
	app, b := syslogField(b)
	_, b = syslogField(b) // PROCID
	_, b = syslogField(b) // MSGID
	l.Host = syslogNil(host)
	l.Program = syslogProgram(syslogNil(app))
	switch {
	case len(b) > 0 && b[0] == '-':
		b = b[1:]
	case len(b) > 0 && b[0] == '[':
		if n := syslogSDEnd(b); n > 0 {
			b = b[n:]
		}
	}
	if len(b) > 0 && b[0] == ' ' {
		b = b[1:]
	}
	l.Message = string(bytes.TrimPrefix(b, syslogBOM))
	var t time.Time
	if len(ts) > 1 {
		t, _ = time.Parse(time.RFC3339, string(ts))
	}
	return t
}

// syslogSDEnd liefert die Laenge der Structured Data ([...][...]) mit Anfuehrungszeichen und Escapes; 0 = kaputt.
func syslogSDEnd(b []byte) int {
	i := 0
	for i < len(b) && b[i] == '[' {
		j, quoted, closed := i+1, false, false
		for ; j < len(b); j++ {
			c := b[j]
			if quoted {
				if c == '\\' {
					j++
				} else if c == '"' {
					quoted = false
				}
				continue
			}
			if c == '"' {
				quoted = true
			} else if c == ']' {
				closed = true
				break
			}
		}
		if !closed {
			return 0
		}
		i = j + 1
	}
	return i
}

// syslogProgram entfernt eine PID ("sshd[123]" -> "sshd").
func syslogProgram(s string) string {
	if i := strings.IndexByte(s, '['); i > 0 {
		return s[:i]
	}
	return s
}

var syslogMonths = [12]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

// syslogParse3164 fuellt Host, Program und Message; liefert die Zeit der Nachricht (Null = keine).
func syslogParse3164(l *LogLine, b []byte, now time.Time) time.Time {
	t, n := syslog3164Time(b, now)
	if n == 0 {
		t, n = syslogISOTime(b)
	}
	hasTime := n > 0
	if hasTime {
		b = bytes.TrimLeft(b[n:], " ")
	}
	tok1, rest1 := syslogField(b)
	if !syslogIsTag(tok1) && syslogIsHost(tok1) {
		if hasTime {
			l.Host, b = string(tok1), rest1
		} else if tok2, _ := syslogField(rest1); syslogIsTag(tok2) {
			l.Host, b = string(tok1), rest1
		}
	}
	b = bytes.TrimLeft(b, " ")
	if tok, rest := syslogField(b); syslogIsTag(tok) {
		l.Program = syslogProgram(string(tok[:len(tok)-1]))
		b = bytes.TrimLeft(rest, " ")
	}
	l.Message = string(b)
	return t
}

// syslog3164Time erkennt "Mmm dd hh:mm:ss" (Tag auch einstellig oder mit Leerzeichen, optional Sekundenbruchteil)
// und liefert Zeit (lokale Zeitzone, Jahr passend zu now) und Laenge; 0 = keine Zeit.
func syslog3164Time(b []byte, now time.Time) (time.Time, int) {
	if len(b) < 14 || b[3] != ' ' {
		return time.Time{}, 0
	}
	mon := 0
	for i, m := range syslogMonths {
		if string(b[:3]) == m {
			mon = i + 1
			break
		}
	}
	if mon == 0 {
		return time.Time{}, 0
	}
	i := 4
	if b[i] == ' ' {
		i++
	}
	day := 0
	for d := 0; d < 2 && i < len(b) && b[i] >= '0' && b[i] <= '9'; d++ {
		day = day*10 + int(b[i]-'0')
		i++
	}
	if day < 1 || day > 31 || i+9 > len(b) || b[i] != ' ' {
		return time.Time{}, 0
	}
	i++
	c := b[i : i+8]
	if c[2] != ':' || c[5] != ':' || !syslogDigits(c[0:2]) || !syslogDigits(c[3:5]) || !syslogDigits(c[6:8]) {
		return time.Time{}, 0
	}
	hh, mm, ss := int(c[0]-'0')*10+int(c[1]-'0'), int(c[3]-'0')*10+int(c[4]-'0'), int(c[6]-'0')*10+int(c[7]-'0')
	if hh > 23 || mm > 59 || ss > 60 {
		return time.Time{}, 0
	}
	i += 8
	nsec := 0
	if i < len(b) && b[i] == '.' {
		j, scale := i+1, 100000000
		for j < len(b) && b[j] >= '0' && b[j] <= '9' {
			nsec += int(b[j]-'0') * scale
			scale /= 10
			j++
		}
		i = j
	}
	if i < len(b) && b[i] != ' ' {
		return time.Time{}, 0
	}
	loc := time.Local // Geraete senden Ortszeit ohne Zone (Container meist UTC, sonst TZ setzen)
	year := now.In(loc).Year()
	t := time.Date(year, time.Month(mon), day, hh, mm, ss, nsec, loc)
	// Jahreswechsel: Nachricht vom 31.12., empfangen am 1.1. (oder umgekehrt bei vorgehender Uhr)
	if t.Sub(now) > 24*time.Hour {
		t = time.Date(year-1, time.Month(mon), day, hh, mm, ss, nsec, loc)
	} else if now.Sub(t) > 24*time.Hour {
		if t2 := time.Date(year+1, time.Month(mon), day, hh, mm, ss, nsec, loc); t2.Sub(now) <= 24*time.Hour {
			t = t2
		}
	}
	return t, i
}

// syslogISOTime erkennt einen RFC-3339-Zeitstempel am Anfang (rsyslog u. a. im RFC-3164-Rahmen).
func syslogISOTime(b []byte) (time.Time, int) {
	if len(b) < 20 || !syslogDigits(b[:4]) || b[4] != '-' || b[7] != '-' || b[10] != 'T' {
		return time.Time{}, 0
	}
	tok, _ := syslogField(b)
	t, err := time.Parse(time.RFC3339, string(tok))
	if err != nil {
		return time.Time{}, 0
	}
	return t, len(tok)
}

// syslogIsTag erkennt "name:" bzw. "name[pid]:" (Name aus Buchstaben, Ziffern und _-./@).
func syslogIsTag(tok []byte) bool {
	if len(tok) < 2 || len(tok) > 64 || tok[len(tok)-1] != ':' {
		return false
	}
	name := tok[:len(tok)-1]
	if i := bytes.IndexByte(name, '['); i >= 0 {
		pid := name[i+1:]
		if i == 0 || len(pid) < 2 || pid[len(pid)-1] != ']' {
			return false
		}
		name = name[:i]
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '/' || c == '@') {
			return false
		}
	}
	return true
}

// syslogIsHost erkennt einen Hostnamen bzw. eine Adresse (auch UniFi "U7PG2,f09fc2000000,v6.5.28").
func syslogIsHost(tok []byte) bool {
	if len(tok) == 0 || len(tok) > 255 {
		return false
	}
	for _, c := range tok {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == ':' || c == ',') {
			return false
		}
	}
	return true
}
