package cdn64

import (
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
	d := dockerData{Tabs: m.tabs("/cdn64/docker"), View: m.dockerView(ctx), On: m.core.SettingOr(ctx, setDocker, "") == "on",
		Traefik: m.core.SettingOr(ctx, setDockerTraefik, "") != "off", Host: m.core.SettingOr(ctx, setDockerHost, ""),
		DefaultHost: proxmox.DefaultDockerHost(), Cert: m.core.SettingOr(ctx, setDockerCert, ""), Errors: map[string]string{}}
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
	ctx := r.Context()
	on, traefik := r.PostFormValue("docker") == "on", r.PostFormValue("traefik") == "on"
	host, cert := strings.TrimSpace(r.PostFormValue("docker_host")), r.PostFormValue("docker_cert")
	fail := func(field, msg string) {
		d := m.dockerData(r)
		d.On, d.Traefik, d.Host, d.Cert = on, traefik, host, cert
		d.Errors[field] = msg
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/docker", "cdn64.docker.title", d)
	}
	// nur der Docker-Host dieser Node: lokaler Socket bzw. docker-socket-proxy (kein ssh://)
	if host != "" && (strings.HasPrefix(host, "ssh://") || !proxmox.ValidDockerHost(host)) {
		fail("docker_host", m.g.T(r, "cdn64.docker.err.docker_host"))
		return
	}
	if !dockerCertOK(cert) {
		fail("docker_cert", m.g.T(r, "cdn64.docker.err.cert"))
		return
	}
	// Zertifikate von Let's Encrypt nur mit angenommenen Nutzungsbedingungen (einmal hier statt je Host)
	if cert != "" && m.certs != nil {
		if acc := m.certs.Account(ctx); !acc.TOSAccepted {
			if r.PostFormValue("accept_tos") != "on" {
				fail("docker_cert", m.g.T(r, "certs.err.tos"))
				return
			}
			if err := m.certs.SetAccount(ctx, acc.Email, true); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			m.g.Audit(r, "cert.account", "", "accept_tos=true")
		}
	}
	vOn, vTraefik := "", "off"
	if on {
		vOn = "on"
	}
	if traefik {
		vTraefik = ""
	}
	for k, v := range map[string]string{setDocker: vOn, setDockerTraefik: vTraefik, setDockerHost: host, setDockerCert: cert} {
		if err := m.core.SetSetting(ctx, k, v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	m.g.Audit(r, "cdn64.docker.settings", "", fmt.Sprintf("docker=%v traefik=%v host=%q cert=%q", on, traefik, host, cert))
	m.dockerKick()
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/cdn64/docker", http.StatusSeeOther)
}
