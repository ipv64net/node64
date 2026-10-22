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
	for _, want := range []string{"docker.conn.ssh", "docker.howto.ssh1", `id="dk-host"`, "docker.form.genkey"} {
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
