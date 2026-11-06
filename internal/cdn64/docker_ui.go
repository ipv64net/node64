package cdn64

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Seite PROXY64 -> Docker: Einstellungen fuer Proxy-Hosts aus Docker-Labels und Liste der Container (Abgleich: docker.go).

func (m *Module) dockerRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /cdn64/docker", page(m.pageDocker))
	mux.Handle("POST /cdn64/docker", page(m.pageDockerSave))
}

type dockerData struct {
	Tabs        []tab
	View        dockerView
	On, Traefik bool
	Host        string // eingestellte Docker-API ("" = Standard)
	DefaultHost string // Standard (NODE64_DOCKER_HOST bzw. Socket)
	Cert        string // Zertifikat fuer neue Docker-Hosts ("" = keins)
	CertsOn     bool   // Zertifikatsverwaltung vorhanden
	ACME        certs.Account
	DNS         []*certs.DNSAccount
	DNSKey      bool // ipv64 DNS-01 moeglich (API-Key)
	Errors      map[string]string
}

func (m *Module) dockerData(r *http.Request) dockerData {
	ctx := r.Context()
	s := m.dockerSettingsOf(ctx)
	d := dockerData{Tabs: m.tabs("/cdn64/docker"), View: m.dockerView(ctx), On: s.Enabled, Traefik: s.Traefik, Host: s.Host,
		DefaultHost: proxmox.DefaultDockerHost(), Cert: s.Cert, Errors: map[string]string{}}
	if m.certs != nil {
		d.CertsOn = true
		d.ACME = m.certs.Account(ctx)
		d.DNS, _ = m.certs.DNSAccounts(ctx)
		d.DNSKey = m.certs.DNSReady(ctx)
	}
	return d
}

func (m *Module) pageDocker(w http.ResponseWriter, r *http.Request) {
	m.g.Render(w, r, http.StatusOK, Name+"/docker", "cdn64.docker.title", m.dockerData(r))
}

// dockerCertOK: "" (keins) oder ein ACME-Weg wie im Host-Formular (auto, ipv64, http, dns:<Zugang>).
func dockerCertOK(v string) bool {
	switch v {
	case "", "auto", "ipv64", "http":
		return true
	}
	id, ok := strings.CutPrefix(v, "dns:")
	n, err := strconv.ParseInt(id, 10, 64)
	return ok && err == nil && n > 0
}

func (m *Module) pageDockerSave(w http.ResponseWriter, r *http.Request) {
	s := dockerSettings{Enabled: r.PostFormValue("docker") == "on", Traefik: r.PostFormValue("traefik") == "on",
		Host: strings.TrimSpace(r.PostFormValue("docker_host")), Cert: r.PostFormValue("docker_cert")}
	if err := m.dockerSave(r, s, r.PostFormValue("accept_tos") == "on"); err != nil {
		var fe *FieldError
		if !errors.As(err, &fe) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		d := m.dockerData(r)
		d.On, d.Traefik, d.Host, d.Cert = s.Enabled, s.Traefik, s.Host, s.Cert
		d.Errors[fe.Field] = m.g.T(r, fe.Key)
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/docker", "cdn64.docker.title", d)
		return
	}
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/cdn64/docker", http.StatusSeeOther)
}

// dockerSettings: Einstellungen des Docker-Abgleichs (Seite und API).
type dockerSettings struct {
	Enabled bool   `json:"enabled"`
	Traefik bool   `json:"traefik"`     // auch Traefik-Labels lesen
	Host    string `json:"docker_host"` // Docker-API ("" = Standard)
	Cert    string `json:"certificate"` // Zertifikat fuer neue Docker-Hosts: "" (keins), auto, ipv64, http, dns:<Zugang>
}

func (m *Module) dockerSettingsOf(ctx context.Context) dockerSettings {
	return dockerSettings{Enabled: m.core.SettingOr(ctx, setDocker, "") == "on", Traefik: m.core.SettingOr(ctx, setDockerTraefik, "") != "off",
		Host: m.core.SettingOr(ctx, setDockerHost, ""), Cert: m.core.SettingOr(ctx, setDockerCert, "")}
}

// dockerSave prueft und speichert die Einstellungen (FieldError: docker_host, docker_cert); acceptTOS nimmt die
// Nutzungsbedingungen von Let's Encrypt an, wenn ein Zertifikat gewaehlt und das Konto noch ohne ist.
func (m *Module) dockerSave(r *http.Request, s dockerSettings, acceptTOS bool) error {
	ctx := r.Context()
	// nur der Docker-Host dieser Node: lokaler Socket bzw. docker-socket-proxy (kein ssh://)
	if s.Host != "" && (strings.HasPrefix(s.Host, "ssh://") || !proxmox.ValidDockerHost(s.Host)) {
		return ferr("docker_host", "cdn64.docker.err.docker_host")
	}
	if !dockerCertOK(s.Cert) {
		return ferr("docker_cert", "cdn64.docker.err.cert")
	}
	// Zertifikate von Let's Encrypt nur mit angenommenen Nutzungsbedingungen (einmal hier statt je Host)
	if s.Cert != "" && m.certs != nil {
		if acc := m.certs.Account(ctx); !acc.TOSAccepted {
			if !acceptTOS {
				return ferr("docker_cert", "certs.err.tos")
			}
			if err := m.certs.SetAccount(ctx, acc.Email, true); err != nil {
				return err
			}
			m.g.Audit(r, "cert.account", "", "accept_tos=true")
		}
	}
	vOn, vTraefik := "", "off"
	if s.Enabled {
		vOn = "on"
	}
	if s.Traefik {
		vTraefik = ""
	}
	for k, v := range map[string]string{setDocker: vOn, setDockerTraefik: vTraefik, setDockerHost: s.Host, setDockerCert: s.Cert} {
		if err := m.core.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	m.g.Audit(r, "cdn64.docker.settings", "", fmt.Sprintf("docker=%v traefik=%v host=%q cert=%q", s.Enabled, s.Traefik, s.Host, s.Cert))
	m.dockerKick()
	return nil
}
