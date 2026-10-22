package dnsserver

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Dynamische Updates (RFC 2136): nur mit gueltigem TSIG-Schluessel der Zone und nur aus erlaubten Netzen. Die
// Pruefung der Signatur macht miekg/dns mit unserem TsigProvider (Schluessel aus dem Modul, aenderbar im Betrieb).

// Updater nimmt geprufte Updates entgegen.
type Updater interface {
	// TSIGSecret: Schluessel (Base64) zum Namen (klein, ohne Punkt am Ende).
	TSIGSecret(name string) (string, bool)
	// Update wendet die Aenderungen auf zone an (key = Name des Schluessels) und liefert den Rcode.
	Update(zone, key string, r *dns.Msg) int
}

// acceptUpdates laesst neben Anfragen auch Updates durch (miekg/dns lehnt sie sonst mit NOTIMP ab).
func acceptUpdates(dh dns.Header) dns.MsgAcceptAction {
	if int(dh.Bits>>11)&0xF == dns.OpcodeUpdate {
		if dh.Qdcount != 1 {
			return dns.MsgReject
		}
		return dns.MsgAccept
	}
	return dns.DefaultMsgAcceptFunc(dh)
}

type tsigProvider struct{ u Updater }

func (p tsigProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	secret, ok := p.u.TSIGSecret(strings.TrimSuffix(strings.ToLower(t.Hdr.Name), "."))
	if !ok {
		return nil, dns.ErrSecret
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	var h hash.Hash
	switch dns.CanonicalName(t.Algorithm) {
	case dns.HmacSHA256:
		h = hmac.New(sha256.New, raw)
	case dns.HmacSHA512:
		h = hmac.New(sha512.New, raw)
	case dns.HmacSHA384:
		h = hmac.New(sha512.New384, raw)
	case dns.HmacSHA1:
		h = hmac.New(sha1.New, raw)
	default:
		return nil, dns.ErrKeyAlg
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

func (p tsigProvider) Verify(msg []byte, t *dns.TSIG) error {
	b, err := p.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil || !hmac.Equal(b, mac) {
		return dns.ErrSig
	}
	return nil
}

// update beantwortet ein Update: ohne TSIG REFUSED, falsche Signatur NOTAUTH, sonst das Ergebnis des Moduls
// (die Antwort ist mit demselben Schluessel signiert).
func (s *Server) update(w dns.ResponseWriter, r *dns.Msg) *dns.Msg {
	ip := remoteIP(w.RemoteAddr())
	if s.Updates == nil || !s.acl.allowed(ip) {
		return errorMsg(r, dns.RcodeRefused)
	}
	t := r.IsTsig()
	if t == nil || len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeSOA {
		return errorMsg(r, dns.RcodeRefused)
	}
	m := new(dns.Msg)
	m.SetReply(r)
	if err := w.TsigStatus(); err != nil {
		s.Logger.Warn("dns update rejected", "client", ip, "key", t.Hdr.Name, "err", err)
		m.Rcode = dns.RcodeNotAuth
		return m // unsigniert: der Schluessel stimmt nicht
	}
	zone := strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
	m.Rcode = s.Updates.Update(zone, strings.TrimSuffix(strings.ToLower(t.Hdr.Name), "."), r)
	s.Logger.Info("dns update", "client", ip, "zone", zone, "key", t.Hdr.Name, "rcode", dns.RcodeToString[m.Rcode])
	m.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
	return m
}
