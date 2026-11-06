package healthchecks

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Docker-Hosts in der JSON-API: was der Assistent der Oberflaeche kann (Verbindungstest mit Fingerabdruck, Schluessel
// erzeugen, Zugangsdaten einzeln aendern, lokalen Host einrichten). Private Schluessel werden nie ausgegeben, nur der
// oeffentliche SSH-Schluessel (credentials.public_key).

// dockerCredsIn: Zugangsdaten einzeln (statt secret). Ohne secret bleiben gespeicherte Teile, die nicht mitkommen.
type dockerCredsIn struct {
	PrivateKey  *string `json:"private_key"`  // SSH- bzw. TLS-Client-Schluessel (PEM); leer = unveraendert
	Cert        *string `json:"cert"`         // TLS-Client-Zertifikat (PEM); "" = Zertifikat und Schluessel entfernen
	CA          *string `json:"ca"`           // CA des Docker-Daemons (PEM); "" = entfernen
	GenerateKey bool    `json:"generate_key"` // SSH: neuen Schluessel erzeugen (der oeffentliche steht in credentials.public_key)
}

func (c dockerCredsIn) set() bool {
	return c.PrivateKey != nil || c.Cert != nil || c.CA != nil || c.GenerateKey
}

// only: einzelne Zugangsdaten gibt es nur fuer Docker-Hosts.
func (c dockerCredsIn) only(sys *proxmox.System) error {
	if c.set() && !sys.IsDocker() {
		return &proxmox.FieldError{Field: "private_key", Key: "pve.err.kind"}
	}
	return nil
}

// dockerCredsJSON zeigt, welche Zugangsdaten gespeichert sind (nur Hosts per SSH bzw. TLS).
type dockerCredsJSON struct {
	Key       bool   `json:"key"`
	Cert      bool   `json:"cert"`
	CA        bool   `json:"ca"`
	PublicKey string `json:"public_key,omitempty"` // SSH: Zeile fuer authorized_keys
}

func dockerCredsOf(sys *proxmox.System) *dockerCredsJSON {
	host := dockerSysHost(sys)
	if !sys.IsDocker() || !proxmox.DockerUsesSecret(host) {
		return nil
	}
	c := proxmox.ParseDockerCreds(sys.Secret)
	out := &dockerCredsJSON{Key: c.Key != "", Cert: c.Cert != "", CA: c.CA != ""}
	if dockerConnOf(host) == dockerConnSSH && c.Key != "" {
		out.PublicKey = proxmox.DockerSSHPublicKey(c.Key)
	}
	return out
}

// dockerAPICreds setzt das Secret aus den einzelnen Zugangsdaten wie das Formular (dockerCredsFor): gespeicherte Teile
// bleiben, ausser die Art der Verbindung wechselt (dann gelten Zugangsdaten und Pin der alten Art nicht mehr). Ein
// ganzes secret ersetzt wie bisher alles.
func dockerAPICreds(old, sys *proxmox.System, in pveSystemIn) error {
	conn := dockerConnOf(strings.TrimSpace(dockerSysHost(sys)))
	connChanged := old != nil && dockerConnOf(dockerSysHost(old)) != conn
	if connChanged && in.PinSHA256 == nil {
		sys.PinSHA256 = ""
	}
	if in.Secret != "" {
		if in.set() {
			return &proxmox.FieldError{Field: "secret", Key: "docker.err.key"} // entweder secret oder einzeln
		}
		return nil
	}
	if !in.set() && !connChanged { // leer = behalten
		return nil
	}
	creds := proxmox.DockerCreds{}
	if old != nil && !connChanged {
		creds = proxmox.ParseDockerCreds(old.Secret)
	}
	var key, ca, cert string
	if in.PrivateKey != nil {
		key = strings.TrimSpace(*in.PrivateKey)
	}
	if in.GenerateKey {
		if conn != dockerConnSSH {
			return &proxmox.FieldError{Field: "generate_key", Key: "docker.err.key"}
		}
		k, err := proxmox.GenerateDockerSSHKey()
		if err != nil {
			return err
		}
		key = strings.TrimSpace(k)
	}
	if in.CA != nil {
		ca = strings.TrimSpace(*in.CA)
	}
	if in.Cert != nil {
		cert = strings.TrimSpace(*in.Cert)
	}
	creds = dockerCredsFor(conn, creds, key, ca, cert, in.CA != nil && ca == "", in.Cert != nil && cert == "")
	sys.Secret = creds.Encode()
	if sys.Secret == "" && old != nil && old.Secret != "" { // leer heisst beim Speichern sonst „behalten“
		sys.Secret = proxmox.DockerNoCreds
	}
	return nil
}

// dockerAPIPrepare: Zugangsdaten setzen und doppelte Adresse ablehnen (wie das Formular).
func (m *Module) dockerAPIPrepare(ctx context.Context, old, sys *proxmox.System, in pveSystemIn) error {
	if err := dockerAPICreds(old, sys, in); err != nil {
		return err
	}
	addr := checks.DefaultDockerHost()
	for _, a := range sys.Addresses {
		if a = strings.TrimSpace(a); a != "" {
			addr = a
			break
		}
	}
	var id int64
	if old != nil {
		id = old.ID
	}
	dup, err := m.dockerDuplicate(ctx, id, addr)
	if err != nil {
		return err
	}
	if dup {
		return &proxmox.FieldError{Field: "addresses", Key: "docker.err.duplicate"}
	}
	return nil
}

// dockerSameEndpoint: gleiche Adresse und gleicher Pin (nur dann gilt das gespeicherte Secret im Test).
func dockerSameEndpoint(a, b *proxmox.System) bool {
	pa, okA := proxmox.NormalizeDockerPin(a.PinSHA256)
	pb, okB := proxmox.NormalizeDockerPin(b.PinSHA256)
	return okA && okB && pa == pb && strings.TrimSpace(dockerSysHost(a)) == strings.TrimSpace(dockerSysHost(b))
}

// dockerProbeJSON ist das Ergebnis von POST /api/healthchecks/docker/probe.
type dockerProbeJSON struct {
	OK                 bool                `json:"ok"`
	Error              string              `json:"error,omitempty"`
	Fingerprint        string              `json:"fingerprint,omitempty"`         // Hex, als pin_sha256 verwendbar
	FingerprintDisplay string              `json:"fingerprint_display,omitempty"` // SSH: SHA256:…, TLS: mit Doppelpunkten
	Trusted            bool                `json:"trusted"`                       // TLS: Zertifikat von CA bzw. System-CA bestaetigt
	NeedConfirm        bool                `json:"need_confirm,omitempty"`        // erst den Fingerabdruck als pin_sha256 bestaetigen
	PinDiffers         bool                `json:"pin_differs,omitempty"`         // gesehener Fingerabdruck passt nicht zum Pin
	Info               *proxmox.DockerInfo `json:"info,omitempty"`
	Containers         int                 `json:"containers"`
	Running            int                 `json:"running"`
	Warning            string              `json:"warning,omitempty"`
	PublicKey          string              `json:"public_key,omitempty"` // SSH: benutzter Schluessel (authorized_keys)
}

// apiDockerProbe testet einen Docker-Host wie der Assistent (Felder wie POST systems, dazu system_id): mit system_id
// gelten die gespeicherten Zugangsdaten nur fuer dieselbe Adresse und denselben Pin. Ohne Pin kommt bei SSH bzw. nicht
// bestaetigtem TLS-Zertifikat erst der Fingerabdruck (need_confirm); danach mit ihm als pin_sha256 erneut testen.
func (m *Module) apiDockerProbe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		pveSystemIn
		SystemID int64 `json:"system_id"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.GenerateKey { // der Test speichert nichts: Schluessel ueber POST/PUT systems erzeugen
		m.pveAPIErr(w, &proxmox.FieldError{Field: "generate_key", Key: "docker.err.key"})
		return
	}
	sys := proxmox.System{Kind: proxmox.KindDocker, Name: "probe", Interval: proxmox.DefaultInterval}
	var old *proxmox.System
	if in.SystemID > 0 {
		var err error
		if old, err = m.pve.st.System(r.Context(), in.SystemID); err != nil {
			m.pveAPIErr(w, err)
			return
		}
		if !old.IsDocker() {
			m.pveAPIErr(w, &proxmox.FieldError{Field: "kind", Key: "pve.err.kind"}) // Proxmox: POST /api/healthchecks/proxmox/probe
			return
		}
		sys = *old
	}
	in.apply(&sys)
	sys.Kind = proxmox.KindDocker
	base := old
	if old != nil && !dockerSameEndpoint(old, &sys) {
		if in.Secret == "" && !in.set() && !proxmox.ParseDockerCreds(old.Secret).Empty() && proxmox.DockerUsesSecret(dockerSysHost(&sys)) {
			m.pveAPIErr(w, &proxmox.FieldError{Field: "secret", Key: "pve.err.secret_reenter"})
			return
		}
		base = nil
	}
	if err := dockerAPICreds(base, &sys, in.pveSystemIn); err != nil {
		m.pveAPIErr(w, err)
		return
	}
	if sys.Secret == "" && base != nil {
		sys.Secret = base.Secret
	}
	if err := proxmox.ValidateSystem(&sys, true); err != nil && !dockerPinOnly(err) {
		m.pveAPIErr(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	host := dockerSysHost(&sys)
	m.auditText(r, "proxmox.probe", host)
	res := dockerProbe(ctx, sys)
	conn := dockerConnOf(host)
	pin, _ := proxmox.NormalizeDockerPin(sys.PinSHA256)
	out := dockerProbeJSON{OK: res.OK, Error: res.Error, Fingerprint: res.Fingerprint, FingerprintDisplay: dockerPinFmt(conn, res.Fingerprint),
		Trusted: res.Trusted, NeedConfirm: res.NeedConfirm, PinDiffers: pin != "" && res.Fingerprint != "" && pin != res.Fingerprint,
		Info: res.Info, Containers: res.Containers, Running: res.Running, Warning: res.Warning}
	if c := proxmox.ParseDockerCreds(sys.Secret); conn == dockerConnSSH && c.Key != "" {
		out.PublicKey = proxmox.DockerSSHPublicKey(c.Key)
	}
	writeJSON(w, http.StatusOK, out)
}

// apiDockerEnable richtet den lokalen Docker-Host ein bzw. schaltet ihn ein (wie der Knopf der leeren Uebersicht):
// nur wenn der Socket erreichbar ist, sonst 422.
func (m *Module) apiDockerEnable(w http.ResponseWriter, r *http.Request) {
	sys, err := m.dockerEnsure(r.Context(), true)
	if sys == nil {
		msg := "docker socket " + checks.DefaultDockerHost() + " not reachable"
		if err != nil {
			msg += ": " + err.Error()
		}
		writeErr(w, http.StatusUnprocessableEntity, msg)
		return
	}
	m.auditText(r, "proxmox.enable", sys.Name)
	writeJSON(w, http.StatusOK, m.pveJSON(r.Context(), sys))
}
