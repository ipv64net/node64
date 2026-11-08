package dns64

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDocker liefert /containers/json aus list (fail = Fehler 500).
type fakeDocker struct {
	mu   sync.Mutex
	list []map[string]any
	fail bool
}

func (f *fakeDocker) set(list []map[string]any, fail bool) {
	f.mu.Lock()
	f.list, f.fail = list, fail
	f.mu.Unlock()
}

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail || !strings.HasSuffix(r.URL.Path, "/containers/json") {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(f.list)
}

func container(name string, labels map[string]string, ip string) map[string]any {
	return map[string]any{"Names": []string{"/" + name}, "State": "running", "Labels": labels,
		"HostConfig":      map[string]any{"NetworkMode": "lan"},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"lan": map[string]any{"IPAddress": ip}}}}
}

// Docker-Labels node64.dns.* legen Eintraege an, aendern und entfernen sie; fremde Namen und Lesefehler bleiben
// unberuehrt (GitHub #18).
func TestDockerDNS(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	fd := &fakeDocker{}
	srv := httptest.NewServer(fd)
	defer srv.Close()
	oldHost, oldWait := dockerDNSHost, dockerDNSRemoveWait
	dockerDNSHost, dockerDNSRemoveWait = func() string { return srv.URL }, time.Hour
	defer func() { dockerDNSHost, dockerDNSRemoveWait = oldHost, oldWait }()
	_ = m.core.SetSetting(ctx, setDocker, "1")
	_ = m.core.SetSetting(ctx, setDockerIP, "192.168.1.5, fd00::5")
	if _, err := m.AddRecord(ctx, Record{Name: "taken.lan", Type: "A", Value: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	fd.set([]map[string]any{
		container("nas", map[string]string{dockerLabelName: "NAS.lan, files.lan"}, "172.17.0.2"),
		container("mac", map[string]string{dockerLabelName: "mac.lan", dockerLabelIP: "container"}, "192.168.1.50"),
		container("bad", map[string]string{dockerLabelName: "bad.lan", dockerLabelIP: "kein-ip"}, ""),
		container("zz-dup", map[string]string{dockerLabelName: "nas.lan"}, ""),
		container("taker", map[string]string{dockerLabelName: "taken.lan"}, ""),
		container("plain", map[string]string{"other": "x"}, ""),
	}, false)
	m.dockerSync(ctx)

	got := func() map[string]Record {
		recs, err := m.Records(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]Record{}
		for _, r := range recs {
			out[r.Name+" "+r.Type+" "+r.Value] = r
		}
		return out
	}
	recs := got()
	for _, k := range []string{"nas.lan A 192.168.1.5", "nas.lan AAAA fd00::5", "files.lan A 192.168.1.5", "mac.lan A 192.168.1.50", "taken.lan A 10.0.0.1"} {
		if _, ok := recs[k]; !ok {
			t.Fatalf("missing %s in %v", k, recs)
		}
	}
	if r := recs["nas.lan A 192.168.1.5"]; r.Comment != "Docker: nas" || !r.LocalOnly {
		t.Fatalf("docker record: %+v", r)
	}
	if len(recs) != 6 { // nas.lan und files.lan je A und AAAA, mac.lan, eigener Eintrag taken.lan
		t.Fatalf("records: %v", recs)
	}
	v := m.DockerDNS(ctx)
	if !v.Enabled || !v.Connected || len(v.Containers) != 5 {
		t.Fatalf("view: %+v", v)
	}
	problems := map[string]string{}
	for _, c := range v.Containers {
		problems[c.Container] = c.Problem
	}
	if problems["nas"] != "" || problems["mac"] != "" || problems["bad"] != dockerErrBadIP || problems["zz-dup"] != dockerErrTaken || problems["taker"] != dockerErrTaken {
		t.Fatalf("problems: %v", problems)
	}

	// Adresse geaendert: alter Eintrag sofort weg, neuer da
	_ = m.core.SetSetting(ctx, setDockerIP, "192.168.1.6")
	m.dockerSync(ctx)
	recs = got()
	if _, ok := recs["nas.lan A 192.168.1.5"]; ok {
		t.Fatalf("old address kept: %v", recs)
	}
	if _, ok := recs["nas.lan A 192.168.1.6"]; !ok {
		t.Fatalf("new address missing: %v", recs)
	}
	if _, ok := recs["nas.lan AAAA fd00::5"]; ok { // keine IPv6 mehr eingestellt, Container noch da
		t.Fatalf("aaaa kept: %v", recs)
	}

	// Lesefehler: nichts loeschen
	fd.set(nil, true)
	m.dockerSync(ctx)
	if _, ok := got()["nas.lan A 192.168.1.6"]; !ok || m.DockerDNS(ctx).Error == "" {
		t.Fatal("api error removed records or no error shown")
	}

	// Container weg: erst nach der Wartezeit
	fd.set([]map[string]any{container("mac", map[string]string{dockerLabelName: "mac.lan", dockerLabelIP: "container"}, "192.168.1.50")}, false)
	m.dockerSync(ctx)
	if _, ok := got()["nas.lan A 192.168.1.6"]; !ok {
		t.Fatal("removed before the wait")
	}
	dockerDNSRemoveWait = 0
	m.dockerSync(ctx)
	recs = got()
	if _, ok := recs["nas.lan A 192.168.1.6"]; ok {
		t.Fatalf("not removed after the wait: %v", recs)
	}
	if _, ok := recs["mac.lan A 192.168.1.50"]; !ok {
		t.Fatalf("running container lost its record: %v", recs)
	}
	if _, ok := recs["taken.lan A 10.0.0.1"]; !ok {
		t.Fatal("own record removed")
	}

	// Schalter aus: Eintraege bleiben, Stand leer
	_ = m.core.SetSetting(ctx, setDocker, "")
	m.dockerSync(ctx)
	if v := m.DockerDNS(ctx); v.Enabled || len(v.Containers) != 0 {
		t.Fatalf("view after off: %+v", v)
	}
	if _, ok := got()["mac.lan A 192.168.1.50"]; !ok {
		t.Fatal("switch off removed records")
	}
}

func TestDockerSettingIP(t *testing.T) {
	for in, ok := range map[string]bool{"": true, "192.168.1.5": true, "192.168.1.5, fd00::1": true, "x": false, "192.168.1.5,nope": false, "0.0.0.0": false} {
		if validDockerIP(in) != ok {
			t.Fatalf("%q: %v", in, !ok)
		}
	}
}
