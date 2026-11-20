package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/store"
)

// Ports der Oberflaeche aus Einstellungen > Allgemein > Erreichbarkeit. Sie gelten vor NODE64_HTTP_PORT und
// NODE64_HTTPS_PORT (das Image setzt NODE64_HTTP_PORT immer); ohne Einstellung gilt die Umgebung. Wirksam nach dem
// Neustart, den das Speichern ausloest (cmd/node64 liest sie vor dem Start der Oberflaeche). Nie im Cluster
// abgeglichen und nicht im Konfigurations-Export: Ports gehoeren zur einzelnen Node.
const (
	SettingHTTPPort  = "web.http_port"
	SettingHTTPSPort = "web.https_port"
)

// WebPorts liefert die eingestellten Ports der Oberflaeche, je Port mit Rueckfall auf die Umgebung; set=false ohne
// Einstellung.
func WebPorts(ctx context.Context, st *store.Store, envHTTP, envHTTPS int) (httpPort, httpsPort int, set bool) {
	httpPort, httpsPort = envHTTP, envHTTPS
	if v, err := strconv.Atoi(st.SettingOr(ctx, SettingHTTPPort, "")); err == nil {
		httpPort, set = v, true
	}
	if v, err := strconv.Atoi(st.SettingOr(ctx, SettingHTTPSPort, "")); err == nil {
		httpsPort, set = v, true
	}
	return httpPort, httpsPort, set
}

// bridgeNet: Container im Docker-Bridge-Netz (Tests: fest).
var bridgeNet = localnet.Bridge

// envPorts: Ports aus der Umgebung (ohne Angabe, z. B. in Tests: die laufenden).
func (s *Server) envPorts() (int, int) {
	if s.Cfg.EnvHTTPPort == 0 && s.Cfg.EnvHTTPSPort == 0 {
		return s.Cfg.HTTPPort, s.Cfg.HTTPSPort
	}
	return s.Cfg.EnvHTTPPort, s.Cfg.EnvHTTPSPort
}

// errPortField: Eingabe ist keine Zahl.
var errPortField = errors.New("not a port number")

// portField liest ein Port-Feld: leer = def.
func portField(r *http.Request, name string, def int) (int, error) {
	v := strings.TrimSpace(r.PostFormValue(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, errPortField
	}
	return n, nil
}

// webPortsError uebersetzt einen Fehler beim Speichern der Ports.
func (s *Server) webPortsError(v *View, err error) string {
	var ce *ports.ConflictError
	switch {
	case errors.Is(err, errPortField), errors.Is(err, config.ErrPortRange):
		return v.T("ports.err_port")
	case errors.Is(err, config.ErrPortsOff):
		return v.T("settings.reach_err_off")
	case errors.Is(err, config.ErrPortsSame):
		return v.T("settings.reach_err_same")
	case errors.As(err, &ce):
		return v.T("settings.reach_err_conflict", "port", strconv.Itoa(ce.Want.Port), "with", ce.With.Owner+" ("+ce.With.Purpose+")")
	}
	return v.T("settings.reach_err_busy", "error", err.Error())
}

// saveWebPorts prueft und speichert die Ports aus dem Formular (Felder http_port, leer = Umgebung, und https_port,
// leer = aus; fehlen beide, bleibt alles). changed = die wirksamen Ports aendern sich, dann muss Node64 neu starten.
func (s *Server) saveWebPorts(r *http.Request) (changed bool, httpPort, httpsPort int, err error) {
	if !r.PostForm.Has("http_port") && !r.PostForm.Has("https_port") {
		return false, 0, 0, nil
	}
	envHTTP, envHTTPS := s.envPorts()
	if httpPort, err = portField(r, "http_port", envHTTP); err != nil {
		return false, 0, 0, err
	}
	if httpsPort, err = portField(r, "https_port", 0); err != nil { // leer = aus
		return false, 0, 0, err
	}
	if err = config.CheckWebPorts(httpPort, httpsPort); err != nil {
		return false, 0, 0, err
	}
	changed = httpPort != s.Cfg.HTTPPort || httpsPort != s.Cfg.HTTPSPort
	if changed {
		// nur neue Ports pruefen: gegen die anderen Teile von Node64 und gegen fremde Programme auf dem Host
		var want []ports.Claim
		for _, p := range []int{httpPort, httpsPort} {
			if p > 0 && p != s.Cfg.HTTPPort && p != s.Cfg.HTTPSPort {
				want = append(want, ports.Claim{Owner: "web", Purpose: "HTTP", Proto: ports.TCP, Port: p, Bind: s.Cfg.BindAddr})
			}
		}
		if s.Ports != nil {
			if err = s.Ports.Check(r.Context(), "web", want); err != nil {
				return false, 0, 0, err
			}
		}
		for _, c := range want {
			if err = ports.Probe(ports.TCP, c.Bind, c.Port); err != nil {
				return false, 0, 0, fmt.Errorf("%d: %w", c.Port, err)
			}
		}
	}
	// gleich der Umgebung = keine Einstellung (dann gilt wieder die Umgebung)
	for _, f := range []struct {
		key       string
		val, envV int
	}{{SettingHTTPPort, httpPort, envHTTP}, {SettingHTTPSPort, httpsPort, envHTTPS}} {
		if f.val == f.envV {
			err = s.Store.DeleteSetting(r.Context(), f.key)
		} else {
			err = s.Store.SetSetting(r.Context(), f.key, strconv.Itoa(f.val))
		}
		if err != nil {
			return false, 0, 0, err
		}
	}
	return changed, httpPort, httpsPort, nil
}

// portSwitchURL: Adresse der Einstellungen nach dem Wechsel - gleicher Name bzw. gleiche IP, der neue Port des
// Lauschers, ueber den die Anfrage kam. Kam sie ueber einen anderen Port (z. B. den gemeinsamen Eingang), bleibt die
// Adresse gleich.
func portSwitchURL(r *http.Request, oldHTTP, oldHTTPS, newHTTP, newHTTPS int) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	local := 0
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if ta, ok := a.(*net.TCPAddr); ok {
			local = ta.Port
		}
	}
	port := 0
	switch {
	case local == 0:
	case local == oldHTTP && newHTTP != oldHTTP:
		port = newHTTP
		if port == 0 { // Web-Port aus: auf den HTTPS-Port
			scheme, port = "https", newHTTPS
		}
	case local == oldHTTPS && newHTTPS != oldHTTPS:
		port = newHTTPS
		if port == 0 { // HTTPS-Port aus: auf den Web-Port (spricht auch TLS)
			port = newHTTP
		}
	}
	if port > 0 {
		name := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			name = h
		}
		host = net.JoinHostPort(strings.Trim(name, "[]"), strconv.Itoa(port))
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: "/settings", Fragment: "reach"}).String()
}

// portSwitchData: Seite waehrend des Neustarts auf die neuen Ports.
type portSwitchData struct {
	Target string
	Bridge bool // Docker-Bridge-Netz: Hinweis auf -p
}

// renderPortSwitch zeigt die Wartesache; app.js fragt den neuen Port ab und wechselt dorthin, sobald er antwortet.
func (s *Server) renderPortSwitch(w http.ResponseWriter, r *http.Request, target string) {
	if u, err := url.Parse(target); err == nil { // nur fuer diese Antwort: Abfrage des neuen Ports erlauben
		origin := u.Scheme + "://" + u.Host
		h := w.Header()
		h.Set("Content-Security-Policy", strings.Replace(h.Get("Content-Security-Policy"), "connect-src 'self'", "connect-src 'self' "+origin, 1))
	}
	v := s.view(r, "settings.reach_switch_title")
	v.Data = portSwitchData{Target: target, Bridge: bridgeNet()}
	s.render(w, r, http.StatusOK, "settings_port_switch", v)
}
