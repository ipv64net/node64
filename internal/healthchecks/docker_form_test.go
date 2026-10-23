package healthchecks

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/proxmox"
)

// dockerPostPage schickt ein Formular ohne Weiterleitung und liefert Status und Seite.
func dockerPostPage(t *testing.T, u string, form url.Values) (int, string) {
	t.Helper()
	resp, err := http.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func dockerForm(base url.Values, kv ...string) url.Values {
	f := url.Values{}
	for k, v := range base {
		f[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Set(kv[i], kv[i+1])
	}
	return f
}

// Docker-Host aus der Ferne per SSH: Schluessel erzeugen, Host-Key bestaetigen, speichern, Uebersicht, bearbeiten, loeschen.
func TestDockerRemoteHosts(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, last, _ := newDockerModuleBox(t, pveCore(t), pveBox(t, 7))
	ctx := context.Background()
	dockerGetPage(t, srv, "/healthchecks/docker") // lokaler Host automatisch
	body := dockerGetPage(t, srv, "/healthchecks/docker/new")
	for _, want := range []string{"docker.conn.ssh", "docker.howto.s1", `id="dk-host"`, "docker.form.genkey"} {
		if !strings.Contains(body, want) {
			t.Fatalf("form: %q missing", want)
		}
	}
	fp := strings.Repeat("1f", 32)
	oldProbe := dockerProbe
	dockerProbe = func(_ context.Context, sys proxmox.System) proxmox.DockerProbeResult {
		switch {
		case sys.PinSHA256 == "":
			return proxmox.DockerProbeResult{NeedConfirm: true, Fingerprint: fp}
		case proxmox.ParseDockerCreds(sys.Secret).Key == "":
			return proxmox.DockerProbeResult{Error: "no key", Fingerprint: fp}
		}
		return proxmox.DockerProbeResult{OK: true, Fingerprint: fp, Info: &proxmox.DockerInfo{Name: "far", Version: "27.3.1"}, Containers: 3, Running: 2}
	}
	t.Cleanup(func() { dockerProbe = oldProbe })
	u := srv.URL + "/healthchecks/docker/new"
	base := url.Values{"conn": {"ssh"}, "user": {"node64"}, "host": {"10.0.0.9"}, "interval": {"30"}, "enabled": {"on"}}

	code, body := dockerPostPage(t, u, dockerForm(base, "op", "genkey"))
	d := (*last).(dockerFormData)
	if code != 200 || !strings.HasPrefix(d.PubKey, "ssh-ed25519 ") || d.KeyGen == "" || d.Address != "ssh://node64@10.0.0.9:22" || !strings.Contains(body, `id="dk-pub"`) { // Wert html-kodiert (+)
		t.Fatalf("genkey: %d %+v", code, d)
	}
	key := d.KeyGen
	withKey := dockerForm(base, "key_gen", key, "key_conn", "ssh")
	code, body = dockerPostPage(t, u, dockerForm(withKey, "op", "probe"))
	d = (*last).(dockerFormData)
	if code != 200 || d.Probe == nil || !d.Probe.NeedConfirm || d.ProbePin != fp || !strings.Contains(body, proxmox.PinBase64(fp)) || d.KeyGen != key {
		t.Fatalf("probe ohne pin: %d %+v", code, d)
	}
	confirmed := dockerForm(withKey, "probe_pin", fp, "pin_confirm", "on")
	code, _ = dockerPostPage(t, u, dockerForm(confirmed, "op", "probe"))
	d = (*last).(dockerFormData)
	if code != 200 || d.Probe == nil || !d.Probe.OK || !d.PinConfirm || d.Sys.Name != "far" {
		t.Fatalf("probe bestaetigt: %d %+v", code, d)
	}
	// ohne bestaetigten Host-Key nicht speichern
	if code, _ = dockerPostPage(t, u, dockerForm(withKey, "op", "save")); code != http.StatusUnprocessableEntity {
		t.Fatalf("ohne pin gespeichert: %d", code)
	}
	if d = (*last).(dockerFormData); d.Errors["pin_sha256"] == "" {
		t.Fatalf("pin-fehler: %+v", d.Errors)
	}
	code, loc := dockerPost(t, srv, "/healthchecks/docker/new", dockerForm(confirmed, "op", "save", "name", "far"))
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/healthchecks/docker/system/") {
		t.Fatalf("save: %d %q", code, loc)
	}
	id, _ := strconv.ParseInt(strings.TrimPrefix(loc, "/healthchecks/docker/system/"), 10, 64)
	sys, err := m.pve.st.System(ctx, id)
	if err != nil || sys.Addresses[0] != "ssh://node64@10.0.0.9:22" || sys.PinSHA256 != fp || proxmox.ParseDockerCreds(sys.Secret).Key != key+"\n" || sys.Name != "far" {
		t.Fatalf("gespeichert: %+v %v", sys, err)
	}
	if code, _ = dockerPostPage(t, u, dockerForm(confirmed, "op", "save")); code != http.StatusUnprocessableEntity || (*last).(dockerFormData).Errors["host"] != "docker.err.duplicate" {
		t.Fatalf("doppelt: %d", code)
	}

	// Uebersicht ab zwei Hosts
	body = dockerGetPage(t, srv, "/healthchecks/docker")
	hd, ok := (*last).(dockerHostsData)
	if !ok || len(hd.Hosts) != 2 || hd.Sum.Systems != 2 || !strings.Contains(body, `id="docker-hosts"`) || !strings.Contains(body, "far") || !strings.Contains(body, "docker.local") {
		t.Fatalf("uebersicht: %T %+v", *last, hd)
	}
	// Host-Seite
	body = dockerGetPage(t, srv, dockerSysPath(id))
	if dd := (*last).(dockerData); dd.Hosts != 2 || dd.Local || dd.Sys.ID != id || !strings.Contains(body, dockerSysPath(id)+"/edit") {
		t.Fatalf("host-seite: %+v", dd)
	}
	// Bearbeiten: gespeicherter Schluessel nur als oeffentlicher
	body = dockerGetPage(t, srv, dockerSysPath(id)+"/edit")
	ed := (*last).(dockerFormData)
	if !ed.Edit || !ed.HasKey || ed.PubKey == "" || ed.Conn != "ssh" || ed.F["host"] != "10.0.0.9" || ed.F["user"] != "node64" || strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("edit: %+v", ed)
	}
	if !strings.Contains(body, proxmox.PinBase64(fp)) {
		t.Fatal("edit: pin fehlt")
	}
	code, _ = dockerPost(t, srv, dockerSysPath(id)+"/edit", dockerForm(base, "op", "save", "name", "far2", "pin_present", "1", "pin_sha256", proxmox.PinBase64(fp)))
	if sys, _ = m.pve.st.System(ctx, id); code != http.StatusSeeOther || sys.Name != "far2" || proxmox.ParseDockerCreds(sys.Secret).Key != key+"\n" || sys.PinSHA256 != fp {
		t.Fatalf("edit save: %d %+v", code, sys)
	}
	// Proxmox-Formular leitet auf das Docker-Formular
	if code, loc = dockerPost(t, srv, "/healthchecks/proxmox/system/"+strconv.FormatInt(id, 10)+"/edit", url.Values{}); loc != dockerSysPath(id)+"/edit" {
		t.Fatalf("pve-form redirect: %d %q", code, loc)
	}
	// Loeschen: lokaler Host bleibt eingerichtet (kein „off“)
	if code, _ = dockerPost(t, srv, "/healthchecks/proxmox/system/"+strconv.FormatInt(id, 10)+"/delete", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("delete: %d", code)
	}
	if m.core.SettingOr(ctx, dockerSettingMonitor, "") == "off" {
		t.Fatal("entfernter Fern-Host schaltet die lokale Einrichtung ab")
	}
	dockerGetPage(t, srv, "/healthchecks/docker")
	if _, ok := (*last).(dockerData); !ok {
		t.Fatalf("ein Host: %T", *last)
	}
}

func TestDockerAddressFields(t *testing.T) {
	for _, tc := range []struct {
		conn string
		f    map[string]string
		want string
	}{
		{"ssh", map[string]string{"user": "u", "host": "h"}, "ssh://u@h:22"},
		{"ssh", map[string]string{"user": "u", "host": "fd00::1", "port": "2222", "sshsock": "/run/user/1000/docker.sock"}, "ssh://u@[fd00::1]:2222/run/user/1000/docker.sock"},
		{"tls", map[string]string{"host": "h"}, "https://h:2376"},
		{"tcp", map[string]string{"host": "proxy", "port": "2375"}, "tcp://proxy:2375"},
		{"local", map[string]string{"socket": "/var/run/docker.sock"}, "unix:///var/run/docker.sock"},
		{"tcp", map[string]string{}, ""},
	} {
		got := dockerAddress(tc.conn, tc.f)
		if got != tc.want {
			t.Errorf("%s %v: %q", tc.conn, tc.f, got)
			continue
		}
		if got == "" {
			continue
		}
		if c := dockerConnOf(got); c != tc.conn {
			t.Errorf("%s: conn %q", got, c)
		}
		if back := dockerAddress(tc.conn, dockerFieldsOf(got)); back != got {
			t.Errorf("%s: zurueck %q", got, back)
		}
	}
}

// Review-Funde: Pause bei ssh, Adresswechsel, Artwechsel, Loeschen, Adresse bleibt, Test ohne Host, Import.
func TestDockerRemoteLifecycle(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, last, _ := newDockerModuleBox(t, pveCore(t), pveBox(t, 9))
	ctx := context.Background()
	fp := strings.Repeat("2e", 32)
	key, _ := proxmox.GenerateDockerSSHKey()
	sshForm := func(kv ...string) url.Values {
		return dockerForm(url.Values{"conn": {"ssh"}, "user": {"node64"}, "host": {"10.0.0.9"}, "interval": {"30"}, "enabled": {"on"},
			"name": {"far"}, "pin_present": {"1"}, "pin_conn": {"ssh"}, "pin_sha256": {proxmox.PinBase64(fp)}, "op": {"save"}}, kv...)
	}
	code, loc := dockerPost(t, srv, "/healthchecks/docker/new", sshForm("key", key))
	if code != http.StatusSeeOther {
		t.Fatalf("anlegen: %d", code)
	}
	id, _ := strconv.ParseInt(strings.TrimPrefix(loc, "/healthchecks/docker/system/"), 10, 64)
	pvePollNow(t, m, id)
	if _, l := dockerPost(t, srv, "/healthchecks/proxmox/system/"+strconv.FormatInt(id, 10)+"/ascheck", url.Values{"key": {"docker/web"}, "on": {"1"}}); l == "" {
		t.Fatal("als check")
	}
	check := func() *Check {
		set, _ := m.pve.st.Settings(ctx, id)
		it := set.Item("docker/web")
		if it == nil || it.CheckToken == "" {
			return nil
		}
		c, _ := m.st.Check(ctx, it.CheckToken)
		return c
	}
	c := check()
	if c == nil || c.Paused || dockerCheckHost(c) != "ssh://node64@10.0.0.9:22" {
		t.Fatalf("check: %+v", c)
	}
	// ausschalten pausiert (ssh braucht die Abfrage), einschalten setzt fort
	toggle := "/healthchecks/proxmox/system/" + strconv.FormatInt(id, 10) + "/toggle"
	dockerPost(t, srv, toggle, url.Values{})
	if c = check(); !c.Paused {
		t.Fatal("ssh-check beim Ausschalten nicht pausiert")
	}
	dockerPost(t, srv, toggle, url.Values{})
	if c = check(); c.Paused {
		t.Fatal("ssh-check nach Einschalten noch pausiert")
	}
	edit := dockerSysPath(id) + "/edit"
	// anderer Port: Check folgt, Verlauf bleibt (gleiche Maschine)
	if code, _ = dockerPost(t, srv, edit, sshForm("port", "2222")); code != http.StatusSeeOther {
		t.Fatalf("port: %d", code)
	}
	if c = check(); dockerCheckHost(c) != "ssh://node64@10.0.0.9:2222" {
		t.Fatalf("check-host nach portwechsel: %s", dockerCheckHost(c))
	}
	set, _ := m.pve.st.Settings(ctx, id)
	if it := set.Item("docker/web"); it == nil || !it.SeenRunning {
		t.Fatal("gleiche maschine: laufend gesehen verloren")
	}
	// andere Maschine: „laufend gesehen“ des alten Hosts gilt nicht mehr
	if code, _ = dockerPost(t, srv, edit, sshForm("host", "10.0.0.10", "port", "2222")); code != http.StatusSeeOther {
		t.Fatalf("host: %d", code)
	}
	set, _ = m.pve.st.Settings(ctx, id)
	if it := set.Item("docker/web"); it == nil || it.SeenRunning || !it.AsCheck {
		t.Fatalf("andere maschine: %+v", it)
	}
	if c = check(); dockerCheckHost(c) != "ssh://node64@10.0.0.10:2222" {
		t.Fatalf("check-host nach hostwechsel: %s", dockerCheckHost(c))
	}
	// Art wechseln: alte Zugangsdaten und Pin gelten nicht (pin_conn der alten Art)
	tls := url.Values{"conn": {"tls"}, "host": {"10.0.0.10"}, "interval": {"30"}, "enabled": {"on"}, "name": {"far"}, "op": {"save"},
		"pin_present": {"1"}, "pin_conn": {"ssh"}, "pin_sha256": {proxmox.PinBase64(fp)}}
	if code, _ = dockerPost(t, srv, edit, tls); code != http.StatusSeeOther {
		t.Fatalf("tls: %d", code)
	}
	sys, _ := m.pve.st.System(ctx, id)
	if sys.Secret != "" || sys.PinSHA256 != "" || sys.Addresses[0] != "https://10.0.0.10:2376" {
		t.Fatalf("nach artwechsel: secret=%v pin=%q addr=%v", sys.Secret != "", sys.PinSHA256, sys.Addresses)
	}
	if code, _ = dockerPostPage(t, srv.URL+edit, sshForm("host", "10.0.0.10")); code != http.StatusUnprocessableEntity || (*last).(dockerFormData).Errors["key"] == "" {
		t.Fatalf("ssh ohne schluessel: %d", code)
	}
	// Loeschen eines TLS-Hosts nimmt seine Checks mit (ohne Abfrage gingen sie nicht)
	tok := check().Token
	dockerPost(t, srv, "/healthchecks/proxmox/system/"+strconv.FormatInt(id, 10)+"/delete", url.Values{})
	if c, _ := m.st.Check(ctx, tok); c != nil {
		t.Fatal("tls-check nach loeschen noch da")
	}
	// tcp-Host: Checks fragen selbst und bleiben beim Loeschen
	code, loc = dockerPost(t, srv, "/healthchecks/docker/new", url.Values{"conn": {"tcp"}, "host": {"proxy"}, "port": {"2375"}, "interval": {"30"},
		"enabled": {"on"}, "name": {"px"}, "op": {"save"}})
	if code != http.StatusSeeOther {
		t.Fatalf("tcp: %d", code)
	}
	id, _ = strconv.ParseInt(strings.TrimPrefix(loc, "/healthchecks/docker/system/"), 10, 64)
	pvePollNow(t, m, id)
	dockerPost(t, srv, "/healthchecks/proxmox/system/"+strconv.FormatInt(id, 10)+"/ascheck", url.Values{"key": {"docker/web"}, "on": {"1"}})
	tok = check().Token
	dockerPost(t, srv, "/healthchecks/proxmox/system/"+strconv.FormatInt(id, 10)+"/delete", url.Values{})
	if c, _ := m.st.Check(ctx, tok); c == nil {
		t.Fatal("tcp-check beim loeschen verloren")
	}
	// Adresse ohne Port bleibt beim Speichern unveraendert
	x := &proxmox.System{Kind: proxmox.KindDocker, Name: "px2", Addresses: []string{"https://docker.example.com"}, Interval: 30, Enabled: false}
	if err := m.pve.st.SaveSystem(ctx, x); err != nil {
		t.Fatal(err)
	}
	if code, _ = dockerPost(t, srv, dockerSysPath(x.ID)+"/edit", url.Values{"conn": {"tls"}, "host": {"docker.example.com"}, "interval": {"30"},
		"name": {"neu"}, "op": {"save"}, "pin_present": {"1"}, "pin_conn": {"tls"}}); code != http.StatusSeeOther {
		t.Fatalf("edit px2: %d", code)
	}
	if got, _ := m.pve.st.System(ctx, x.ID); got.Addresses[0] != "https://docker.example.com" || got.Name != "neu" {
		t.Fatalf("adresse umgeschrieben: %v", got.Addresses)
	}
	// Test ohne Host prueft nicht den lokalen Socket
	if code, _ = dockerPostPage(t, srv.URL+"/healthchecks/docker/new", url.Values{"conn": {"ssh"}, "user": {"u"}, "op": {"probe"}}); code != http.StatusUnprocessableEntity ||
		(*last).(dockerFormData).Errors["host"] == "" {
		t.Fatalf("test ohne host: %d", code)
	}
	// Import: Eintrag ohne Adressen bricht nicht ab; TLS-Host ohne Zugangsdaten (Export ohne Passwort) kommt abgeschaltet
	n, err := m.pveImport(ctx, []pveExportSystem{{Kind: proxmox.KindDocker, Name: "leer", Interval: 30},
		{Kind: proxmox.KindDocker, Name: "tlsimp", Addresses: []string{"https://imp.example:2376"}, HasSecret: true, Interval: 30, Enabled: true}})
	if n < 1 {
		t.Fatalf("import: %d %v", n, err)
	}
	list, _ := m.dockerSystems(ctx)
	for _, s := range list {
		if s.Name == "tlsimp" && s.Enabled {
			t.Fatal("tls-host ohne zugangsdaten eingeschaltet importiert")
		}
	}
}
