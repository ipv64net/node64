package honeypot

import (
	"crypto/tls"
	"net"
	"net/netip"
	"time"
)

// Fallen-Dienste Stufe 2 (weitere Protokolle): jede Datei meldet ihre Dienste per init() an, sensor.go oeffnet sie
// ueber diese Liste. So kommen neue Dienste ohne Aenderung an sensor.go, module.go oder bei ipv64 dazu (ipv64 nimmt
// neue Dienste und Arten an, wenn sie dem Muster folgen).
//
// Regeln fuer alle Dienste: Low Interaction – nie etwas ausfuehren, keine ausgehenden Verbindungen, jede Anmeldung
// ablehnen (nach kurzer, zufaelliger Pause), Ein- und Ausgabe begrenzen (trapConn hat ein Byte-Budget, dazu eigene
// Zeitlimits mit SetDeadline), Zugangsdaten mit s.login(e) melden (Username/Password), alles andere mit s.emit(e).
// Banner neutral oder wie die verbreitete Standardausgabe des Protokolls, keine Markennamen in eigenen Texten.

// TCPProto ist ein Dienst auf TCP.
type TCPProto struct {
	Service string // Svc*
	TLS     bool   // erst TLS mit dem Zertifikat des Sensors (z. B. MikroTik API-SSL)
	Budget  int64  // Bytes, die je Verbindung gelesen werden (0 = sensorTCPBudget)
	Handle  func(s *Sensor, c *trapConn)
}

// UDPProto ist ein Dienst auf UDP. Handle laeuft, bis pc geschlossen wird (ReadFrom liefert dann einen Fehler), und
// begrenzt Antworten selbst (keine Verstaerkung: Antwort nie groesser als die Anfrage, hoechstens eine je Anfrage,
// Rate-Limit je Quelle).
type UDPProto struct {
	Service string
	Handle  func(s *Sensor, t *trapService, pc net.PacketConn)
}

var (
	tcpProtos = map[string]*TCPProto{}
	udpProtos = map[string]*UDPProto{}
)

// RegisterTCP meldet einen TCP-Dienst an (nur aus init()).
func RegisterTCP(p *TCPProto) { tcpProtos[p.Service] = p }

// RegisterUDP meldet einen UDP-Dienst an (nur aus init()).
func RegisterUDP(p *UDPProto) { udpProtos[p.Service] = p }

// ProtoKnown: Dienst aus Stufe 2 bekannt.
func ProtoKnown(service string) bool { return tcpProtos[service] != nil || udpProtos[service] != nil }

// ProtoUDP: Dienst laeuft auf UDP (Port-Pruefung und Claims mit udp).
func ProtoUDP(service string) bool { return udpProtos[service] != nil }

// udpEvent liefert ein vorbelegtes Ereignis fuer eine UDP-Anfrage.
func (t *trapService) udpEvent(kind string, from netip.AddrPort) Event {
	return Event{Time: time.Now(), Service: t.key.Service, Port: t.key.Port, Kind: kind, Src: from.Addr().Unmap(), SrcPort: int(from.Port())}
}

// serveProtoTLS fuehrt den TLS-Handshake (Zeitlimit) und gibt die Verbindung dann an den Dienst; danach liest und
// schreibt c ueber TLS (Budget zaehlt den Klartext). cert ist das selbst signierte Zertifikat; ein Zertifikat der
// Verwaltung hat Vorrang (sensor_cert.go). Der angefragte Name (SNI) steht danach in den Ereignissen (Host).
func (s *Sensor) serveProtoTLS(c *trapConn, cert *tls.Certificate, p *TCPProto) {
	if cert == nil {
		return
	}
	tc := tls.Server(c.Conn, s.tlsConfigFor(c.t.key, func() (*tls.Certificate, error) { return cert, nil }))
	_ = tc.SetDeadline(time.Now().Add(sensorTCPWait))
	if err := tc.Handshake(); err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	c.sni = storeClip(tc.ConnectionState().ServerName, MaxText)
	c.Conn = tc
	p.Handle(s, c)
}
