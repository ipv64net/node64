package honeypot

import (
	"crypto/tls"
	"slices"
)

// Gueltige Zertifikate fuer Koeder-Namen: HTTPS-Fallen mit Webserver-Profil (nginx, Apache) und die Mail-Fallen mit
// TLS (SMTPS 465, IMAPS 993, POP3S 995) zeigen auf Wunsch ein Zertifikat der zentralen Zertifikatsverwaltung der Node
// (Config.CertID) statt des selbst signierten. Profile, die in echt selbst signiert sind (Proxmox, Webmin, NAS,
// UniFi, Router-Geraete, Grafana, Home Assistant, Elasticsearch usw.), bleiben selbst signiert, ausser ihr Port
// steht in Config.CertPorts. Die Fallen lesen nur das Zertifikat; ausgestellt und erneuert wird in der Verwaltung.
//
// STARTTLS (25, 587, 110, 143) bieten die Mail-Fallen weiterhin nicht an (Antwort "TLS not available").

// Mail-Fallen mit TLS ab dem ersten Byte (gleiche Sitzung wie SMTP, IMAP, POP3).
const (
	SvcSMTPS = "smtps"
	SvcIMAPS = "imaps"
	SvcPOP3S = "pop3s"
)

func init() {
	RegisterTCP(&TCPProto{Service: SvcSMTPS, TLS: true, Budget: sensorPlainBudget, Handle: (*Sensor).handleSMTP})
	RegisterTCP(&TCPProto{Service: SvcIMAPS, TLS: true, Budget: sensorPlainBudget, Handle: (*Sensor).handleIMAP})
	RegisterTCP(&TCPProto{Service: SvcPOP3S, TLS: true, Budget: sensorPlainBudget, Handle: (*Sensor).handlePOP3})
}

// certSelfPages: Koeder, deren Original selbst signiert ist (Geraete und Admin-Oberflaechen).
var certSelfPages = []string{"pve", "pbs", "nas", "unifi", "webmin", "grafana", "homeassistant", "elastic", "kubelet", "portainer", "docker"}

// certMail: Mail-Fallen mit TLS.
func certMail(service string) bool {
	return service == SvcSMTPS || service == SvcIMAPS || service == SvcPOP3S
}

// CertPublic: der Dienst zeigt das Zertifikat der Verwaltung ohne eigene Zuweisung des Ports (Webserver-Profil
// ohne Geraete-Koeder bzw. Mail mit TLS). persona ist das wirksame Profil des Dienstes.
func CertPublic(service, page, persona string) bool {
	switch {
	case certMail(service):
		return true
	case service == SvcHTTPS:
		return (persona == PersonaNginx || persona == PersonaApache) && !slices.Contains(certSelfPages, page)
	}
	return false
}

// CertCapable: der Dienst kann ueberhaupt ein Zertifikat zeigen (HTTPS und Mail mit TLS; MikroTik API-SSL bleibt
// immer selbst signiert wie das Geraet).
func CertCapable(service string) bool { return service == SvcHTTPS || certMail(service) }

// sensorCertCfg ist die Zuweisung nach dem letzten Apply.
type sensorCertCfg struct {
	id    int64
	ports []int
}

// SetCertSource setzt die Quelle der Zertifikate (Kennung -> gueltiges Zertifikat, nil = keins); nil = keine
// Verwaltung (Modus ohne Oberflaeche), alle Fallen selbst signiert.
func (s *Sensor) SetCertSource(f func(id int64) *tls.Certificate) {
	if f == nil {
		s.certSrc.Store(nil)
		return
	}
	s.certSrc.Store(&f)
}

// realCert liefert das Zertifikat der Verwaltung fuer einen Dienst (nil = selbst signiert wie bisher). Fehlt das
// Zertifikat (geloescht, abgelaufen, noch nicht ausgestellt), bleibt die Falle selbst signiert.
func (s *Sensor) realCert(k sensorKey) *tls.Certificate {
	cc, src := s.certCfg.Load(), s.certSrc.Load()
	if cc == nil || cc.id <= 0 || src == nil || *src == nil || !CertCapable(k.Service) {
		return nil
	}
	if !slices.Contains(cc.ports, k.Port) && !CertPublic(k.Service, k.Page, s.personas().of(k)) {
		return nil
	}
	return (*src)(cc.id)
}

// tlsConfigFor: TLS-Einstellung eines Dienstes mit Zertifikat je Verbindung (Zertifikat der Verwaltung oder fallback).
func (s *Sensor) tlsConfigFor(k sensorKey, fallback func() (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c := s.realCert(k); c != nil {
			return c, nil
		}
		return fallback()
	}}
}
