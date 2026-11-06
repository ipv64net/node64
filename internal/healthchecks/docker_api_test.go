package healthchecks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

// dockerTestPair erzeugt ein selbst signiertes Zertifikat mit Schluessel (PEM) fuer TLS-Zugangsdaten.
func dockerTestPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "docker"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func dockerAPISys(t *testing.T, b []byte) pveSystemJSON {
	t.Helper()
	var out pveSystemJSON
	if err := json.Unmarshal(b, &out); err != nil || out.System == nil {
		t.Fatalf("system json: %v %s", err, b)
	}
	return out
}

// Docker-Hosts nur ueber die API: einrichten, Test mit Fingerabdruck, Schluessel erzeugen, Zugangsdaten einzeln,
// doppelte Adresse.
func TestDockerAPIHosts(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, _, _ := newDockerModuleBox(t, pveCore(t), pveBox(t, 7))
	ctx := context.Background()
	const d = "/api/healthchecks/docker"

	// lokaler Host: einrichten, zweimal ist dasselbe, als neuer Host doppelt
	code, b := call(t, srv, "POST", d+"/enable", nil)
	if code != http.StatusOK || dockerAPISys(t, b).Kind != proxmox.KindDocker {
		t.Fatalf("enable: %d %s", code, b)
	}
	local := dockerSysID(t, m)
	if code, b = call(t, srv, "POST", d+"/enable", nil); code != http.StatusOK || dockerAPISys(t, b).ID != local {
		t.Fatalf("enable again: %d %s", code, b)
	}
	if code, b = call(t, srv, "POST", d+"/systems", map[string]any{}); code != http.StatusUnprocessableEntity || !strings.Contains(string(b), "docker.err.duplicate") {
		t.Fatalf("local twice: %d %s", code, b)
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

	// SSH: erst der Host-Key, dann mit erzeugtem Schluessel anlegen
	addr := "ssh://node64@10.0.0.9:22"
	code, b = call(t, srv, "POST", d+"/probe", map[string]any{"addresses": []string{addr}})
	var pr dockerProbeJSON
	_ = json.Unmarshal(b, &pr)
	if code != http.StatusOK || !pr.NeedConfirm || pr.Fingerprint != fp || pr.FingerprintDisplay != proxmox.PinBase64(fp) {
		t.Fatalf("probe ohne pin: %d %s", code, b)
	}
	if code, b = call(t, srv, "POST", d+"/probe", map[string]any{"addresses": []string{addr}, "generate_key": true}); code != http.StatusUnprocessableEntity {
		t.Fatalf("probe genkey: %d %s", code, b)
	}
	code, b = call(t, srv, "POST", d+"/systems", map[string]any{"name": "far", "addresses": []string{addr}, "pin_sha256": proxmox.PinBase64(fp), "generate_key": true})
	far := dockerAPISys(t, b)
	if code != http.StatusCreated || far.Credentials == nil || !far.Credentials.Key || !strings.HasPrefix(far.Credentials.PublicKey, "ssh-ed25519 ") ||
		strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatalf("create ssh: %d %s", code, b)
	}
	pub := far.Credentials.PublicKey
	code, b = call(t, srv, "GET", fmt.Sprintf(d+"/systems/%d", far.ID), nil)
	if code != http.StatusOK || dockerAPISys(t, b).Credentials.PublicKey != pub {
		t.Fatalf("get: %d %s", code, b)
	}
	code, b = call(t, srv, "POST", d+"/probe", map[string]any{"system_id": far.ID})
	pr = dockerProbeJSON{}
	_ = json.Unmarshal(b, &pr)
	if code != http.StatusOK || !pr.OK || pr.PublicKey != pub || pr.Info == nil || pr.Info.Name != "far" {
		t.Fatalf("probe gespeichert: %d %s", code, b)
	}
	// gespeicherter Schluessel nicht fuer eine andere Adresse
	if code, b = call(t, srv, "POST", d+"/probe", map[string]any{"system_id": far.ID, "addresses": []string{"ssh://node64@10.0.0.10:22"}}); code != http.StatusUnprocessableEntity ||
		!strings.Contains(string(b), "pve.err.secret_reenter") {
		t.Fatalf("probe andere adresse: %d %s", code, b)
	}
	sys, _ := m.pve.st.System(ctx, far.ID)
	key := proxmox.ParseDockerCreds(sys.Secret).Key
	if code, b = call(t, srv, "PUT", fmt.Sprintf(d+"/systems/%d", far.ID), map[string]any{"name": "far2"}); code != http.StatusOK {
		t.Fatalf("rename: %d %s", code, b)
	}
	if sys, _ = m.pve.st.System(ctx, far.ID); sys.Name != "far2" || proxmox.ParseDockerCreds(sys.Secret).Key != key || sys.PinSHA256 != fp {
		t.Fatalf("rename behaelt nicht: %+v", sys)
	}
	if code, b = call(t, srv, "POST", d+"/systems", map[string]any{"addresses": []string{addr}, "pin_sha256": fp, "generate_key": true}); code != http.StatusUnprocessableEntity ||
		!strings.Contains(string(b), "docker.err.duplicate") {
		t.Fatalf("doppelt: %d %s", code, b)
	}
	code, b = call(t, srv, "PUT", fmt.Sprintf(d+"/systems/%d", far.ID), map[string]any{"generate_key": true})
	if np := dockerAPISys(t, b).Credentials.PublicKey; code != http.StatusOK || np == pub || np == "" {
		t.Fatalf("neuer schluessel: %d %s", code, b)
	}
	if code, b = call(t, srv, "PUT", fmt.Sprintf(d+"/systems/%d", far.ID), map[string]any{"secret": "x", "ca": ""}); code != http.StatusUnprocessableEntity {
		t.Fatalf("secret und einzeln: %d %s", code, b)
	}
	// Proxmox-Systeme kennen keine einzelnen Docker-Zugangsdaten
	if code, b = call(t, srv, "POST", "/api/healthchecks/proxmox/systems", map[string]any{"addresses": []string{"10.0.0.1"}, "token_id": "a@pve!b",
		"secret": "s", "generate_key": true}); code != http.StatusUnprocessableEntity {
		t.Fatalf("pve genkey: %d %s", code, b)
	}

	// TLS: Teile einzeln setzen und entfernen
	cert, ckey := dockerTestPair(t)
	code, b = call(t, srv, "POST", d+"/systems", map[string]any{"name": "tls", "addresses": []string{"https://10.0.0.20:2376"}, "ca": cert, "cert": cert, "private_key": ckey})
	tl := dockerAPISys(t, b)
	if code != http.StatusCreated || tl.Credentials == nil || !tl.Credentials.CA || !tl.Credentials.Cert || !tl.Credentials.Key || tl.Credentials.PublicKey != "" {
		t.Fatalf("create tls: %d %s", code, b)
	}
	path := fmt.Sprintf(d+"/systems/%d", tl.ID)
	if code, b = call(t, srv, "PUT", path, map[string]any{"ca": ""}); code != http.StatusOK {
		t.Fatalf("ca entfernen: %d %s", code, b)
	}
	if c := dockerAPISys(t, b).Credentials; c == nil || c.CA || !c.Cert || !c.Key {
		t.Fatalf("ca entfernt: %s", b)
	}
	if code, b = call(t, srv, "PUT", path, map[string]any{"cert": ""}); code != http.StatusOK {
		t.Fatalf("cert entfernen: %d %s", code, b)
	}
	if c := dockerAPISys(t, b).Credentials; c == nil || c.CA || c.Cert || c.Key {
		t.Fatalf("cert entfernt: %s", b)
	}
	// Art gewechselt: Zugangsdaten der alten Art gelten nicht
	call(t, srv, "PUT", path, map[string]any{"ca": cert})
	if code, b = call(t, srv, "PUT", path, map[string]any{"addresses": []string{"tcp://10.0.0.20:2375"}}); code != http.StatusOK || dockerAPISys(t, b).Credentials != nil {
		t.Fatalf("tcp: %d %s", code, b)
	}
	if sys, _ = m.pve.st.System(ctx, tl.ID); sys.Secret != "" {
		t.Fatal("tcp: secret bleibt")
	}
}

// Checks aus Docker-Hosts ueber die API: eigener Name, alle als Check, direkt auf die Statusseite.
func TestDockerAPIChecks(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, _, _ := newDockerModuleRec(t, pveCore(t))
	ctx := context.Background()
	call(t, srv, "POST", "/api/healthchecks/docker/enable", nil)
	id := dockerSysID(t, m)
	pvePollNow(t, m, id)
	base := fmt.Sprintf("/api/healthchecks/docker/systems/%d", id)

	code, b := call(t, srv, "PUT", base+"/settings?key=docker/web", map[string]any{"as_check": true, "name": "Mein Web"})
	if code != http.StatusOK {
		t.Fatalf("as_check: %d %s", code, b)
	}
	set, _ := m.pve.st.Settings(ctx, id)
	webTok := set.Item("docker/web").CheckToken
	if c, _ := m.st.Check(ctx, webTok); c == nil || c.Name != "Mein Web" {
		t.Fatalf("name: %+v", c)
	}
	if code, b = call(t, srv, "POST", base+"/ascheck-all?scope=x", nil); code != http.StatusBadRequest {
		t.Fatalf("scope: %d %s", code, b)
	}
	var res struct{ Added, Failed int }
	code, b = call(t, srv, "POST", base+"/ascheck-all", nil)
	_ = json.Unmarshal(b, &res)
	if code != http.StatusOK || res.Added != 2 || res.Failed != 0 { // db und cache (tmp hat nomonitor, web ist schon Check)
		t.Fatalf("all: %d %s", code, b)
	}
	code, b = call(t, srv, "POST", base+"/ascheck-all", nil)
	_ = json.Unmarshal(b, &res)
	if code != http.StatusOK || res.Added != 0 {
		t.Fatalf("all again: %d %s", code, b)
	}
	// Proxmox-Pfad nimmt dasselbe System
	if code, b = call(t, srv, "POST", fmt.Sprintf("/api/healthchecks/proxmox/systems/%d/ascheck-all?scope=nodes", id), nil); code != http.StatusOK {
		t.Fatalf("pve path: %d %s", code, b)
	}

	// Statusseite: Check und Container (Check fehlt: wird angelegt)
	call(t, srv, "PUT", base+"/settings?key=docker/cache", map[string]any{"as_check": false})
	code, b = call(t, srv, "POST", "/api/status-pages", map[string]any{"title": "Status", "slug": "status"})
	var p StatusPage
	if err := json.Unmarshal(b, &p); code != http.StatusCreated || err != nil {
		t.Fatalf("page: %d %s", code, b)
	}
	items := fmt.Sprintf("/api/status-pages/%d/items", p.ID)
	add := map[string]any{"tokens": []string{webTok}, "resources": []map[string]any{{"system_id": id, "key": "docker/cache"}, {"system_id": id, "key": "docker/web"}}}
	code, b = call(t, srv, "POST", items, add)
	p = StatusPage{}
	if err := json.Unmarshal(b, &p); code != http.StatusOK || err != nil || len(p.Groups) != 1 || len(p.Groups[0].Items) != 2 {
		t.Fatalf("items: %d %s", code, b)
	}
	set, _ = m.pve.st.Settings(ctx, id)
	if it := set.Item("docker/cache"); it == nil || !it.AsCheck || it.CheckToken == "" {
		t.Fatalf("cache check fehlt: %+v", it)
	}
	code, b = call(t, srv, "POST", items, add)
	p = StatusPage{}
	if err := json.Unmarshal(b, &p); code != http.StatusOK || err != nil || len(p.Groups) != 1 || len(p.Groups[0].Items) != 2 {
		t.Fatalf("items again: %d %s", code, b)
	}
	for _, bad := range []map[string]any{{"tokens": []string{"nope"}}, {"resources": []map[string]any{{"system_id": id, "key": "x"}}},
		{"resources": []map[string]any{{"system_id": 999, "key": "docker/web"}}}, {"group_id": 999, "tokens": []string{webTok}}} {
		if code, b = call(t, srv, "POST", items, bad); code != http.StatusUnprocessableEntity {
			t.Fatalf("bad %v: %d %s", bad, code, b)
		}
	}
}
