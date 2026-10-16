package web

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/certs"
)

// Zertifikat der Oberflaeche (HTTPS-Port und Name am Eingang) aus der zentralen Verwaltung. Reihenfolge:
// NODE64_TLS_CERT (Container-Konfiguration) > gewaehltes Zertifikat > automatisch (passendes Zertifikat zum
// aufgerufenen Namen) > selbst signiert. Gewechselt wird je Handshake, ohne Neustart.

const setUICert = "web.tls_cert" // auto | self | <Kennung>

// uiCertValue liest die Einstellung: -1 = selbst signiert, 0 = automatisch, sonst Kennung.
func uiCertValue(v string) int64 {
	switch v {
	case "", "auto":
		return 0
	case "self":
		return -1
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

func uiCertString(id int64) string {
	switch {
	case id < 0:
		return "self"
	case id == 0:
		return "auto"
	}
	return strconv.FormatInt(id, 10)
}

func (s *Server) loadUICert(ctx context.Context) {
	s.uiCertSel.Store(uiCertValue(s.Store.SettingOr(ctx, setUICert, "auto")))
}

// uiCertificate liefert das Zertifikat fuer einen Handshake am HTTPS-Port der Oberflaeche.
func (s *Server) uiCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.Cfg.TLSCertFile != "" || s.Certs == nil { // fest per Umgebung
		return s.fallbackCert, nil
	}
	switch id := s.uiCertSel.Load(); {
	case id > 0:
		if c := s.Certs.ByID(id); c != nil {
			return c, nil
		}
	case id == 0 && hello.ServerName != "":
		if c := s.Certs.ForName(hello.ServerName); c != nil {
			return c, nil
		}
	}
	return s.fallbackCert, nil
}

// saveUICert prueft und speichert die Auswahl, dann wird der Name am Eingang neu angemeldet.
func (s *Server) saveUICert(r *http.Request, value string) error {
	value = strings.TrimSpace(value)
	id := uiCertValue(value)
	if value != "" && value != "auto" && value != "self" && id == 0 {
		return errors.New("invalid certificate")
	}
	if id > 0 {
		if s.Certs == nil {
			return errors.New("no certificate manager")
		}
		if _, err := s.Certs.Get(r.Context(), id); err != nil {
			return errors.New("unknown certificate")
		}
	}
	old := s.uiCertSel.Load()
	if old == id {
		return nil
	}
	ctx := context.WithoutCancel(r.Context())
	if err := s.Store.SetSetting(ctx, setUICert, uiCertString(id)); err != nil {
		return err
	}
	s.uiCertSel.Store(id)
	if err := s.uiRoute(ctx); err != nil {
		s.log.Warn("web interface not registered at the edge", "err", err)
	}
	s.audit(r, "web.tls_cert", uiCertString(id), "")
	return nil
}

// saveUICertForm: nur wenn das Formular das Feld enthaelt (sonst bliebe die Auswahl nicht erhalten).
func (s *Server) saveUICertForm(r *http.Request) error {
	if !r.PostForm.Has("ui_cert") {
		return nil
	}
	return s.saveUICert(r, r.PostFormValue("ui_cert"))
}

// uiCertUsers: fuer „benutzt von“ in der Verwaltung (Schutz beim Loeschen).
func (s *Server) uiCertUsers(ctx context.Context) map[int64][]string {
	out := map[int64][]string{}
	if s.Cfg.TLSCertFile != "" {
		return out
	}
	id := s.uiCertSel.Load()
	if id == 0 {
		if name := s.Store.SettingOr(ctx, setUIName, ""); name != "" && s.Certs != nil {
			id = s.Certs.MatchID(name)
		}
	}
	if id > 0 {
		out[id] = []string{"Node64-Oberfläche"}
	}
	return out
}

// uiCertView: Auswahl in der Karte Ports.
type uiCertView struct {
	Value     string
	EnvFile   bool // NODE64_TLS_CERT gesetzt: Auswahl ohne Wirkung am HTTPS-Port
	HTTPSPort int
	Certs     []*certs.Cert
}

func (s *Server) uiCertData(ctx context.Context) uiCertView {
	v := uiCertView{Value: uiCertString(s.uiCertSel.Load()), EnvFile: s.Cfg.TLSCertFile != "", HTTPSPort: s.Cfg.HTTPSPort}
	if s.Certs != nil {
		list, _ := s.Certs.List(ctx)
		for _, c := range list {
			if !c.NotAfter.IsZero() {
				v.Certs = append(v.Certs, c)
			}
		}
	}
	return v
}
