package healthchecks

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Mehrere Docker-Hosts wie bei Proxmox VE: Uebersicht ab zwei Hosts (Kacheln ueber alle, Tabelle der Hosts) und das
// Formular fuer Hosts aus der Ferne (docker_remote.go im Paket proxmox): SSH zum Socket, Docker-API mit TLS (2376),
// TCP bzw. docker-socket-proxy (2375) oder ein lokaler Socket. Kein Agent auf dem Host noetig.

// Arten der Verbindung im Formular.
const (
	dockerConnSSH   = "ssh"
	dockerConnTLS   = "tls"
	dockerConnTCP   = "tcp"
	dockerConnLocal = "local"
)

var dockerConns = []string{dockerConnSSH, dockerConnTLS, dockerConnTCP, dockerConnLocal}

// ---------------------------------------------------------------- Uebersicht

// dockerHostRow ist ein Docker-Host der Uebersicht.
type dockerHostRow struct {
	pveSysRow
	Info  *proxmox.DockerInfo
	Local bool
}

type dockerHostsData struct {
	Hosts   []dockerHostRow
	Sum     pveSum // Systems = Hosts, Guests = Container (CPU/RAM: Container bezogen auf die Hosts)
	Last    *pveIncident
	LastURL string
	NoBox   bool
}

func (m *Module) pageDockerHosts(w http.ResponseWriter, r *http.Request, list []*proxmox.System) {
	ctx := r.Context()
	d := dockerHostsData{NoBox: m.pve.box == nil, Last: m.lastIncident(ctx, dockerSettingLast)}
	for _, sys := range list {
		row := dockerHostRow{pveSysRow: m.pveSysView(ctx, sys), Local: proxmox.DockerLocal(dockerSysHost(sys))}
		if s := row.Snap; s != nil && s.OK {
			row.Info = s.Docker
			row.Guests, row.Running = 0, 0 // wie die Host-Seite: alle Container (auch node64.nomonitor)
			for _, x := range s.Resources {
				if x.Type != proxmox.TypeDocker {
					continue
				}
				row.Guests++
				if x.Status == "running" {
					row.CPUCores += x.CPU * x.MaxCPU
					row.Mem += x.Mem
					if !pveRow(sys.ID, x, row.Settings).Bad {
						row.Running++
					}
				}
			}
			if s.Docker != nil {
				row.CPUMax, row.MemMax = float64(s.Docker.NCPU), s.Docker.MemTotal
			}
		}
		d.Sum.add(row.pveSysRow)
		d.Hosts = append(d.Hosts, row)
	}
	if d.Last != nil {
		d.LastURL = pveResPath(d.Last.SystemID, d.Last.Key)
	}
	m.g.Render(w, r, http.StatusOK, Name+"/docker_hosts", "nav.docker", d)
}

// ---------------------------------------------------------------- Formular

type dockerFormData struct {
	Sys          *proxmox.System
	Edit         bool
	Conn         string
	Conns        []string
	F            map[string]string // socket, host, port, user, sshsock, ca, cert (Zertifikate nur im Assistenten)
	KeyGen       string            // eben erzeugter Schluessel (im Formular gehalten, bis gespeichert)
	PubKey       string            // Zeile fuer authorized_keys
	HasKey       bool              // gespeichert (Bearbeiten): leer lassen = behalten
	HasCert      bool
	HasCA        bool
	Address      string
	Probe        *proxmox.DockerProbeResult
	ProbePin     string
	ProbeTrusted bool // Zertifikat von CA bzw. System-CA bestaetigt (Test), bleibt ueber Neuzeichnungen
	ProbeFmt     string
	PinConfirm   bool
	PinFmt       string
	PinDiffers   bool
	Errors       map[string]string
	Error        string
	NoBox        bool
	MinIv        int
	MaxIv        int
}

func (d dockerFormData) Crumb() string {
	if d.Edit {
		return d.Sys.Name
	}
	return ""
}

// dockerConnOf: Art der Verbindung einer Adresse.
func dockerConnOf(host string) string {
	switch proxmox.DockerScheme(host) {
	case "ssh":
		return dockerConnSSH
	case "https":
		return dockerConnTLS
	case "unix":
		return dockerConnLocal
	}
	return dockerConnTCP
}

// dockerFieldsOf zerlegt eine Adresse in die Felder des Formulars.
func dockerFieldsOf(host string) map[string]string {
	f := map[string]string{}
	if strings.HasPrefix(host, "unix://") {
		f["socket"] = strings.TrimPrefix(host, "unix://")
		return f
	}
	u, err := url.Parse(strings.Replace(host, "tcp://", "http://", 1))
	if err != nil {
		return f
	}
	f["host"], f["port"] = u.Hostname(), u.Port()
	if u.Scheme == "ssh" {
		if u.User != nil {
			f["user"] = u.User.Username()
		}
		f["sshsock"] = u.Path
	}
	return f
}

// dockerAddress baut die Adresse aus den Feldern ("" bei fehlendem Host bzw. Socket).
func dockerAddress(conn string, f map[string]string) string {
	if conn == dockerConnLocal {
		sock := strings.TrimSpace(f["socket"])
		if sock == "" {
			return checks.DefaultDockerHost()
		}
		return "unix://" + sock
	}
	host := strings.Trim(strings.TrimSpace(f["host"]), "[]")
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(f["port"])
	switch conn {
	case dockerConnSSH:
		if port == "" {
			port = "22"
		}
		u := url.URL{Scheme: "ssh", User: url.User(strings.TrimSpace(f["user"])), Host: net.JoinHostPort(host, port)}
		if p := strings.TrimSpace(f["sshsock"]); p != "" && p != "/var/run/docker.sock" {
			u.Path = p
		}
		return u.String()
	case dockerConnTLS:
		if port == "" {
			port = "2376"
		}
		return "https://" + net.JoinHostPort(host, port)
	}
	if port == "" {
		port = "2375"
	}
	return "tcp://" + net.JoinHostPort(host, port)
}

func (m *Module) dockerFormOf(sys *proxmox.System, edit bool) dockerFormData {
	d := dockerFormData{Sys: sys, Edit: edit, Conn: dockerConnSSH, Conns: dockerConns, F: map[string]string{}, Errors: map[string]string{},
		NoBox: m.pve.box == nil, MinIv: proxmox.MinInterval, MaxIv: proxmox.MaxInterval, PinFmt: proxmox.PinBase64(sys.PinSHA256)}
	if edit {
		host := dockerSysHost(sys)
		d.Conn, d.F, d.Address = dockerConnOf(host), dockerFieldsOf(host), host
		if d.Conn == dockerConnTLS {
			d.PinFmt = pveFingerprint(sys.PinSHA256)
		}
		c := proxmox.ParseDockerCreds(sys.Secret)
		d.HasKey, d.HasCert, d.HasCA = c.Key != "", c.Cert != "", c.CA != ""
		if d.Conn == dockerConnSSH && c.Key != "" {
			d.PubKey = proxmox.DockerSSHPublicKey(c.Key)
		}
	}
	return d
}

func (m *Module) pageDockerForm(w http.ResponseWriter, r *http.Request) {
	sys := &proxmox.System{Kind: proxmox.KindDocker, Interval: proxmox.DefaultInterval, Enabled: true}
	edit := r.PathValue("id") != ""
	if edit {
		if sys = m.pveSystemOf(w, r); sys == nil {
			return
		}
		if !sys.IsDocker() {
			http.Redirect(w, r, pveResPath(sys.ID, "")+"/edit", http.StatusSeeOther)
			return
		}
	}
	d := m.dockerFormOf(sys, edit)
	if c := r.URL.Query().Get("conn"); !edit && containsStr(dockerConns, c) {
		d.Conn = c
	}
	m.renderDockerForm(w, r, http.StatusOK, d)
}

func (m *Module) renderDockerForm(w http.ResponseWriter, r *http.Request, status int, d dockerFormData) {
	if d.ProbeFmt == "" { // jede Neuzeichnung zeigt den gesehenen Fingerabdruck (nicht nur direkt nach dem Test)
		d.ProbeFmt = dockerPinFmt(d.Conn, d.ProbePin)
	}
	title := "docker.host.add"
	if d.Edit {
		title = "docker.host.edit"
	}
	m.g.Render(w, r, status, Name+"/docker_form", title, d)
}

// dockerProbe ist austauschbar (Tests).
var dockerProbe = proxmox.DockerProbe

func (m *Module) pageDockerSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	edit := r.PathValue("id") != ""
	sys := &proxmox.System{Kind: proxmox.KindDocker}
	var old *proxmox.System
	if edit {
		if old = m.pveSystemOf(w, r); old == nil {
			return
		}
		if !old.IsDocker() {
			http.Redirect(w, r, pveResPath(old.ID, ""), http.StatusSeeOther)
			return
		}
		sys.ID, sys.Created = old.ID, old.Created
	}
	sys.Name = strings.TrimSpace(r.PostFormValue("name"))
	sys.Interval, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("interval")))
	sys.Enabled = r.PostFormValue("enabled") == "on"
	if old == nil {
		sys.PinSHA256 = ""
	} else {
		sys.PinSHA256 = old.PinSHA256
	}
	var d dockerFormData
	if old != nil {
		d = m.dockerFormOf(old, true)
		d.Sys = sys
	} else {
		d = m.dockerFormOf(sys, false)
	}
	if c := r.PostFormValue("conn"); containsStr(dockerConns, c) {
		d.Conn = c
	}
	// Art gewechselt: Zugangsdaten und Pin der alten Art gelten nicht
	connChanged := old != nil && dockerConnOf(dockerSysHost(old)) != d.Conn
	if connChanged {
		d.HasKey, d.HasCert, d.HasCA, d.PubKey, sys.PinSHA256 = false, false, false, "", ""
	}
	d.F = map[string]string{}
	for _, k := range []string{"socket", "host", "port", "user", "sshsock"} {
		d.F[k] = strings.TrimSpace(r.PostFormValue(k))
	}
	d.Address = dockerAddress(d.Conn, d.F)
	if old != nil && !connChanged { // Felder unveraendert: Adresse bleibt wortgleich (ohne Port, mit Pfad, http://)
		if oh := dockerSysHost(old); dockerAddress(d.Conn, dockerFieldsOf(oh)) == d.Address {
			d.Address = oh
		}
	}
	sys.Addresses = []string{d.Address}
	// Zugangsdaten: gespeicherte bleiben, Eingaben ersetzen sie
	creds := proxmox.DockerCreds{}
	if old != nil && !connChanged {
		creds = proxmox.ParseDockerCreds(old.Secret)
	}
	// Schluessel aus diesem Formular (erzeugt bzw. eingefuegt) bleibt bis zum Speichern im Formular (wie das Secret im
	// Proxmox-Assistenten), nur fuer dieselbe Art der Verbindung
	if r.PostFormValue("key_conn") == d.Conn {
		d.KeyGen = strings.TrimSpace(r.PostFormValue("key_gen"))
	}
	if k := strings.TrimSpace(r.PostFormValue("key")); k != "" {
		d.KeyGen = k
	}
	if r.PostFormValue("op") == "genkey" && d.Conn == dockerConnSSH {
		k, err := proxmox.GenerateDockerSSHKey()
		if err != nil {
			m.fail(w, r, err)
			return
		}
		d.KeyGen = strings.TrimSpace(k)
	}
	switch d.Conn {
	case dockerConnSSH:
		if d.KeyGen != "" {
			creds.Key = d.KeyGen + "\n"
		}
		creds.Cert, creds.CA = "", ""
		d.PubKey = proxmox.DockerSSHPublicKey(creds.Key)
	case dockerConnTLS:
		d.F["ca"], d.F["cert"] = strings.TrimSpace(r.PostFormValue("ca")), strings.TrimSpace(r.PostFormValue("cert"))
		if d.F["ca"] != "" {
			creds.CA = d.F["ca"] + "\n"
		}
		if r.PostFormValue("ca_clear") == "on" {
			creds.CA = ""
		}
		if d.F["cert"] != "" {
			creds.Cert = d.F["cert"] + "\n"
		}
		if d.KeyGen != "" {
			creds.Key = d.KeyGen + "\n"
		}
		if r.PostFormValue("cert_clear") == "on" {
			creds.Cert, creds.Key, d.KeyGen = "", "", ""
		}
	default:
		creds, d.KeyGen = proxmox.DockerCreds{}, ""
	}
	sys.Secret = creds.Encode()
	if sys.Secret == "" && old != nil && old.Secret != "" { // leer heisst beim Speichern sonst „behalten“
		sys.Secret = proxmox.DockerNoCreds
	}
	// Pin: im Test gesehener und bestaetigter Fingerabdruck, sonst das Feld (beides nur fuer die Art, fuer die es galt)
	pinOK := r.PostFormValue("pin_conn") == "" || r.PostFormValue("pin_conn") == d.Conn
	if r.PostFormValue("pin_present") == "1" && pinOK { // Feld leeren = Pin entfernen
		sys.PinSHA256 = strings.TrimSpace(r.PostFormValue("pin_sha256"))
	}
	if p, ok := proxmox.NormalizeDockerPin(sys.PinSHA256); ok {
		sys.PinSHA256 = p
	}
	if pinOK {
		d.ProbePin = strings.TrimSpace(r.PostFormValue("probe_pin"))
		d.ProbeTrusted = r.PostFormValue("probe_trusted") == "1"
	}
	d.PinConfirm = r.PostFormValue("pin_confirm") == "on" && d.ProbePin != ""
	if d.ProbePin != "" && d.PinConfirm {
		sys.PinSHA256 = d.ProbePin
	}
	if !proxmox.DockerUsesSecret(d.Address) {
		sys.PinSHA256 = ""
	}
	d.PinFmt = dockerPinFmt(d.Conn, sys.PinSHA256)
	switch r.PostFormValue("op") {
	case "", "genkey": // Art gewechselt bzw. Schluessel erzeugt: nur neu zeigen
		m.renderDockerForm(w, r, http.StatusOK, d)
		return
	case "probe":
		if d.Address == "" { // sonst setzte die Pruefung den lokalen Socket ein
			m.dockerFormErr(w, r, &d, &proxmox.FieldError{Field: "host", Key: "docker.err.host"})
			return
		}
		test := *sys
		if test.Name == "" {
			test.Name = "probe"
		}
		if err := proxmox.ValidateSystem(&test, true); err != nil && !dockerPinOnly(err) {
			m.dockerFormErr(w, r, &d, err)
			return
		}
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		res := dockerProbe(pctx, test)
		cancel()
		d.Probe = &res
		d.ProbePin, d.ProbeFmt, d.ProbeTrusted = res.Fingerprint, dockerPinFmt(d.Conn, res.Fingerprint), res.Trusted
		pin, _ := proxmox.NormalizeDockerPin(sys.PinSHA256)
		d.PinDiffers = pin != "" && res.Fingerprint != "" && pin != res.Fingerprint
		d.PinConfirm = d.PinConfirm && d.ProbePin != "" && pin == res.Fingerprint
		if sys.Name == "" && res.OK && res.Info != nil && res.Info.Name != "" {
			sys.Name = res.Info.Name
		}
		m.renderDockerForm(w, r, http.StatusOK, d)
		return
	}
	// Speichern
	if d.Address == "" {
		m.dockerFormErr(w, r, &d, &proxmox.FieldError{Field: "host", Key: "docker.err.host"})
		return
	}
	if d.Conn == dockerConnSSH && creds.Key == "" { // auch beim Bearbeiten (z. B. nach Wechsel der Art)
		m.dockerFormErr(w, r, &d, &proxmox.FieldError{Field: "key", Key: "docker.err.key"})
		return
	}
	if d.Conn == dockerConnTLS && d.ProbePin != "" && !d.PinConfirm && sys.PinSHA256 == "" && !d.ProbeTrusted {
		m.dockerFormErr(w, r, &d, &proxmox.FieldError{Field: "pin_sha256", Key: "pve.err.pin_confirm"})
		return
	}
	list, err := m.dockerSystems(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	for _, x := range list {
		if x.ID != sys.ID && dockerSysHost(x) == d.Address {
			m.dockerFormErr(w, r, &d, &proxmox.FieldError{Field: "host", Key: "docker.err.duplicate"})
			return
		}
	}
	if sys.Name == "" {
		sys.Name = d.F["host"]
		if d.Conn == dockerConnLocal {
			sys.Name = "Docker"
		}
	}
	if err := m.pveSaveSystem(r, sys); err != nil {
		var fe *proxmox.FieldError
		if !errors.As(err, &fe) && !errors.Is(err, proxmox.ErrNoBox) {
			m.fail(w, r, err)
			return
		}
		m.dockerFormErr(w, r, &d, err)
		return
	}
	if dockerIsLocal(sys) {
		_ = m.core.SetSetting(ctx, dockerSettingMonitor, "")
	}
	m.auditText(r, map[bool]string{true: "proxmox.update", false: "proxmox.create"}[edit], sys.Name)
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, dockerSysPath(sys.ID), http.StatusSeeOther)
}

// dockerPinOnly: im Test darf der Pin fehlen (er wird erst gezeigt und bestaetigt).
func dockerPinOnly(err error) bool {
	var fe *proxmox.FieldError
	return errors.As(err, &fe) && fe.Field == "pin_sha256" && fe.Key == "docker.err.hostkey"
}

// dockerPinFmt zeigt einen Pin: SSH wie ssh-keygen (SHA256:…), TLS wie bei Proxmox (Doppelpunkte).
func dockerPinFmt(conn, pin string) string {
	if pin == "" {
		return ""
	}
	if conn == dockerConnSSH {
		return proxmox.PinBase64(pin)
	}
	return pveFingerprint(pin)
}

func (m *Module) dockerFormErr(w http.ResponseWriter, r *http.Request, d *dockerFormData, err error) {
	var fe *proxmox.FieldError
	if errors.As(err, &fe) {
		d.Errors[fe.Field] = m.g.T(r, fe.Key)
	}
	d.Error = m.pveErrText(r, err)
	m.renderDockerForm(w, r, http.StatusUnprocessableEntity, *d)
}
