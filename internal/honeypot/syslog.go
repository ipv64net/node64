package honeypot

import (
	"context"
	"log/slog"
	"net/netip"
	"time"
)

// Platzhalter (H5 Vertrag): wird vom Teil „Syslog“ ersetzt. Signaturen bleiben.

// SyslogServer nimmt Syslog per UDP und TCP auf einem Port an (RFC 3164 und RFC 5424, TCP mit Zeilenende oder
// Octet-Counting) und gibt jede Nachricht als LogLine (Origin SrcSyslog) an feed. Absender ausserhalb von allow werden
// verworfen und gezaehlt (leeres allow = private Netze und localhost).
type SyslogServer struct {
	log  *slog.Logger
	port int
}

// NewSyslogServer legt den Empfaenger an (noch nicht offen).
func NewSyslogServer(log *slog.Logger, port int, allow []netip.Prefix, feed func(LogLine)) *SyslogServer {
	return &SyslogServer{log: log, port: port}
}

// Start oeffnet UDP und TCP. Ein Fehler steht danach auch in Status().Error.
func (s *SyslogServer) Start(ctx context.Context) error { return nil }

// Stop schliesst alles und wartet auf die Verbindungen.
func (s *SyslogServer) Stop() {}

// Status liefert den Zustand.
func (s *SyslogServer) Status() SyslogStatus { return SyslogStatus{Port: s.port} }

// ParseSyslog zerlegt eine Nachricht (ohne Octet-Count/Zeilenende). from ist der Absender, now die Empfangszeit.
func ParseSyslog(raw []byte, from netip.Addr, now time.Time) LogLine {
	return LogLine{Time: now.UTC(), Origin: SrcSyslog, Format: "syslog", Message: string(raw)}
}
