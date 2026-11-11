package apis

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFritz stellt TR-064 einer FRITZ!Box nach (Dienste, Aktionen und Felder aus den Dokumenten "TR-064 Support"):
// /tr64desc.xml ohne Anmeldung, SOAP nur mit gueltigem HTTP-Digest.
type fakeFritz struct {
	mu       sync.Mutex
	user     string
	pass     string
	nonce    int               // laufende Nummer der ausgegebenen Aufforderung
	resp     map[string]string // "Dienst#Aktion" -> Argumente als XML
	denied   map[string]bool   // "Dienst#Aktion" -> UPnP-Fehler 606
	noDesc   bool
	hits     map[string]int
	rejected int // Anfragen mit 401
}

const fbRealm = "HTTPS Access"

func fbDescXML(services ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>` +
		`<systemVersion><HW>226</HW><Major>154</Major><Minor>8</Minor><Patch>2</Patch><Buildnumber>118482</Buildnumber><Display>154.08.02</Display></systemVersion>` +
		`<device><deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType><friendlyName>FRITZ!Box 7590</friendlyName>` +
		`<modelName>FRITZ!Box 7590</modelName><serviceList>`)
	for _, s := range services {
		b.WriteString(`<service><serviceType>urn:dslforum-org:service:` + s + `:1</serviceType><serviceId>urn:x:serviceId:` + s + `1</serviceId>` +
			`<controlURL>/upnp/control/` + strings.ToLower(s) + `</controlURL><eventSubURL>/upnp/control/` + strings.ToLower(s) + `</eventSubURL><SCPDURL>/x.xml</SCPDURL></service>`)
	}
	b.WriteString(`</serviceList><deviceList><device><modelName>LANDevice - FRITZ!Box 7590</modelName></device></deviceList></device></root>`)
	return b.String()
}

func newFakeFritz() *fakeFritz {
	return &fakeFritz{user: "monitor64", pass: "geheim-fritz-1234", hits: map[string]int{}, denied: map[string]bool{}, resp: map[string]string{
		"Layer3Forwarding#GetDefaultConnectionService": `<NewDefaultConnectionService>1.WANPPPConnection.1</NewDefaultConnectionService>`,
		"WANPPPConnection#GetInfo": `<NewEnable>1</NewEnable><NewConnectionStatus>Connected</NewConnectionStatus><NewUptime>302400</NewUptime>` +
			`<NewLastConnectionError>ERROR_NONE</NewLastConnectionError><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>`,
		"WANIPConnection#GetInfo": `<NewEnable>1</NewEnable><NewConnectionStatus>Disconnected</NewConnectionStatus><NewUptime>0</NewUptime>` +
			`<NewLastConnectionError>ERROR_NO_CARRIER</NewLastConnectionError><NewExternalIPAddress>0.0.0.0</NewExternalIPAddress>`,
		"WANCommonInterfaceConfig#GetCommonLinkProperties": `<NewWANAccessType>DSL</NewWANAccessType><NewLayer1UpstreamMaxBitRate>40000000</NewLayer1UpstreamMaxBitRate>` +
			`<NewLayer1DownstreamMaxBitRate>100000000</NewLayer1DownstreamMaxBitRate><NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus>`,
		"WANCommonInterfaceConfig#X_AVM-DE_GetOnlineMonitor": `<NewTotalNumberSyncGroups>1</NewTotalNumberSyncGroups><NewSyncGroupName>sync_dsl</NewSyncGroupName>` +
			`<Newmax_ds>12500000</Newmax_ds><Newmax_us>5000000</Newmax_us><Newds_current_bps>1250000,900000,0</Newds_current_bps>` +
			`<Newmc_current_bps>250000,0,0</Newmc_current_bps><Newus_current_bps>125000,100,0</Newus_current_bps>`,
		"WANDSLInterfaceConfig#GetInfo": `<NewEnable>1</NewEnable><NewStatus>Up</NewStatus><NewUpstreamCurrRate>40000</NewUpstreamCurrRate>` +
			`<NewDownstreamCurrRate>100000</NewDownstreamCurrRate><NewUpstreamMaxRate>46000</NewUpstreamMaxRate><NewDownstreamMaxRate>130000</NewDownstreamMaxRate>` +
			`<NewUpstreamNoiseMargin>100</NewUpstreamNoiseMargin><NewDownstreamNoiseMargin>90</NewDownstreamNoiseMargin>` +
			`<NewUpstreamAttenuation>120</NewUpstreamAttenuation><NewDownstreamAttenuation>175</NewDownstreamAttenuation>`,
		"WANDSLInterfaceConfig#GetStatisticsTotal": `<NewCRCErrors>40</NewCRCErrors><NewATUCCRCErrors>2</NewATUCCRCErrors><NewFECErrors>9</NewFECErrors>`,
		"DeviceInfo#GetInfo": `<NewManufacturerName>AVM</NewManufacturerName><NewModelName>FRITZ!Box 7590</NewModelName>` +
			`<NewSoftwareVersion>154.08.02</NewSoftwareVersion><NewUpTime>864000</NewUpTime><NewDeviceLog>viel Text &amp; mehr</NewDeviceLog>`,
		"UserInterface#GetInfo": `<NewUpgradeAvailable>0</NewUpgradeAvailable><NewPasswordRequired>1</NewPasswordRequired><NewX_AVM-DE_Version></NewX_AVM-DE_Version>`,
	}}
}

func (f *fakeFritz) challenge(w http.ResponseWriter) {
	f.nonce++
	f.rejected++
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="%s",nonce="N%d",algorithm=MD5,qop="auth"`, fbRealm, f.nonce))
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`<HTML><BODY>401 Unauthorized</BODY></HTML>`))
}

func (f *fakeFritz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/tr64desc.xml" {
		if f.noDesc {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(fbDescXML("DeviceInfo", "Layer3Forwarding", "WANCommonInterfaceConfig", "WANDSLInterfaceConfig", "WANPPPConnection", "WANIPConnection", "UserInterface")))
		return
	}
	c, ok := parseFBChallenge(r.Header.Get("Authorization")) // gleiche Form wie die Aufforderung
	fields := map[string]string{}
	for _, p := range strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Digest "), ", ") {
		k, v, _ := strings.Cut(p, "=")
		fields[k] = strings.Trim(v, `"`)
	}
	want := md5hex(md5hex(f.user+":"+fbRealm+":"+f.pass) + ":" + fields["nonce"] + ":" + fields["nc"] + ":" + fields["cnonce"] + ":auth:" + md5hex("POST:"+r.URL.Path))
	if !ok || c.Nonce != fmt.Sprintf("N%d", f.nonce) || fields["username"] != f.user || fields["response"] != want || fields["uri"] != r.URL.Path {
		f.challenge(w)
		return
	}
	act := strings.Trim(r.Header.Get("SOAPACTION"), `"`)
	svc, action, _ := strings.Cut(strings.TrimPrefix(act, "urn:dslforum-org:service:"), ":1#")
	key := svc + "#" + action
	f.hits[key]++
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	body, known := f.resp[key]
	switch {
	case f.denied[key]:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode>` +
			`<faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:dslforum-org:control-1-0"><errorCode>606</errorCode>` +
			`<errorDescription>Action Not Authorized</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
	case !known:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail>` +
			`<UPnPError xmlns="urn:dslforum-org:control-1-0"><errorCode>401</errorCode><errorDescription>Invalid Action</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
	default:
		_, _ = w.Write([]byte(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
			`<s:Body><u:` + action + `Response xmlns:u="urn:dslforum-org:service:` + svc + `:1">` + body + `</u:` + action + `Response></s:Body></s:Envelope>`))
	}
}

func fritzFor(t *testing.T, f *fakeFritz, pass string) *Fritzbox {
	t.Helper()
	addr, pin := tlsServer(t, f)
	fb, err := NewFritzbox(FritzboxConfig{Address: addr, User: " monitor64 ", Password: pass, Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fb.Close)
	return fb
}

func TestFritzboxCollectDSL(t *testing.T) {
	f := newFakeFritz()
	fb := fritzFor(t, f, f.pass)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fb.now = func() time.Time { return now }
	svcs, err := fb.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", deErr(err))
	}
	if len(svcs) != 4 {
		t.Fatalf("%d Dienste", len(svcs))
	}
	w := svcByKey(t, svcs, "wan")
	if w.Kind != "wan" || len(w.Facts) != 0 || w.Text != "DSL · verbunden seit 3 Tage · 203.0.113.7 · 12 Mbit/s ab / 1,0 Mbit/s auf" {
		t.Errorf("wan: %+v %q", w.Facts, w.Text)
	}
	m := map[string]float64{}
	for _, x := range w.Metrics {
		m[x.Name] = x.Value
	}
	if m["uptime"] != 302400 || m["down"] != 12 || m["up"] != 1 {
		t.Errorf("wan Metriken: %v", m)
	}
	d := svcByKey(t, svcs, "dsl")
	if d.Kind != "dsl" || len(d.Facts) != 0 || d.Text != "Sync 100 Mbit/s ab / 40 Mbit/s auf · Störabstand 9 / 10 dB" {
		t.Errorf("dsl: %+v %q", d.Facts, d.Text)
	}
	dm := map[string]float64{}
	for _, x := range d.Metrics {
		dm[x.Name] = x.Value
	}
	if dm["down"] != 100 || dm["up"] != 40 || dm["snr_down"] != 9 || dm["snr_up"] != 10 || dm["att_down"] != 17.5 || dm["att_up"] != 12 {
		t.Errorf("dsl Metriken: %v", dm)
	}
	if _, has := dm["crc"]; has {
		t.Error("CRC-Fehler schon in der ersten Runde")
	}
	if s := svcByKey(t, svcs, "system"); s.Name != "FRITZ!Box 7590" || s.Text != "FRITZ!OS 154.08.02 · läuft seit 10 Tage" || s.Metrics[0].Value != 864000 {
		t.Errorf("system: %q %q", s.Name, s.Text)
	}
	if u := svcByKey(t, svcs, "updates"); len(u.Facts) != 0 || u.Metrics[0].Value != 0 {
		t.Errorf("updates: %+v", u)
	}

	// zweite Runde: CRC-Fehler seit der vorigen Runde, Update verfuegbar erst nach einer Stunde neu gefragt
	f.mu.Lock()
	f.resp["WANDSLInterfaceConfig#GetStatisticsTotal"] = `<NewCRCErrors>55</NewCRCErrors><NewATUCCRCErrors>3</NewATUCCRCErrors>`
	f.resp["UserInterface#GetInfo"] = `<NewUpgradeAvailable>1</NewUpgradeAvailable><NewX_AVM-DE_Version>154.08.03</NewX_AVM-DE_Version>`
	f.mu.Unlock()
	now = now.Add(time.Minute)
	svcs, err = fb.Collect(context.Background())
	if err != nil {
		t.Fatal(deErr(err))
	}
	for _, x := range svcByKey(t, svcs, "dsl").Metrics {
		if x.Name == "crc" && x.Value != 16 {
			t.Errorf("crc = %v", x.Value)
		}
	}
	if u := svcByKey(t, svcs, "updates"); len(u.Facts) != 0 {
		t.Errorf("updates zu frueh neu gefragt: %+v", u)
	}
	now = now.Add(time.Hour)
	svcs, _ = fb.Collect(context.Background())
	if u := svcByKey(t, svcs, "updates"); len(u.Facts) != 1 || u.Facts[0].Code != "updates_security" || u.Text != "FRITZ!OS-Update verfügbar: 154.08.03" {
		t.Errorf("updates: %+v %q", u.Facts, u.Text)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// eine Aufforderung fuer alle Anfragen; Art der Verbindung wird gemerkt
	if f.rejected != 1 || f.hits["Layer3Forwarding#GetDefaultConnectionService"] != 2 || f.hits["WANPPPConnection#GetInfo"] != 3 || f.hits["WANIPConnection#GetInfo"] != 0 {
		t.Errorf("abgelehnt %d, Abfragen %v", f.rejected, f.hits)
	}
}

// Kabel-Box: Verbindung ueber WANIPConnection, kein DSL-Dienst; Leitung und Verbindung getrennt.
func TestFritzboxCableDown(t *testing.T) {
	f := newFakeFritz()
	f.resp["Layer3Forwarding#GetDefaultConnectionService"] = `<NewDefaultConnectionService>1.WANIPConnection.1</NewDefaultConnectionService>`
	f.resp["WANCommonInterfaceConfig#GetCommonLinkProperties"] = `<NewWANAccessType>X_AVM-DE_Cable</NewWANAccessType><NewPhysicalLinkStatus>Down</NewPhysicalLinkStatus>`
	svcs, err := fritzFor(t, f, f.pass).Collect(context.Background())
	if err != nil {
		t.Fatal(deErr(err))
	}
	for _, s := range svcs {
		if s.Key == "dsl" {
			t.Error("DSL-Dienst an einer Kabel-Box")
		}
	}
	w := svcByKey(t, svcs, "wan")
	if len(w.Facts) != 2 || w.Facts[0].Code != "device_crit" || w.Facts[0].Text != "Leitung nicht verbunden (Down)" ||
		w.Facts[1].Text != "Internetverbindung getrennt (Disconnected) (ERROR_NO_CARRIER)" || !strings.HasPrefix(w.Text, "Kabel · ") {
		t.Errorf("wan: %+v %q", w.Facts, w.Text)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hits["WANDSLInterfaceConfig#GetInfo"] != 0 || f.hits["WANIPConnection#GetInfo"] != 1 {
		t.Errorf("Abfragen %v", f.hits)
	}
}

// Benutzer ohne das Recht "FRITZ!Box Einstellungen": Zugangsart und Update-Stand kommen, der Rest fehlt mit Hinweis.
func TestFritzboxWithoutRights(t *testing.T) {
	f := newFakeFritz()
	for _, k := range []string{"Layer3Forwarding#GetDefaultConnectionService", "WANPPPConnection#GetInfo", "WANIPConnection#GetInfo",
		"WANCommonInterfaceConfig#X_AVM-DE_GetOnlineMonitor", "WANDSLInterfaceConfig#GetInfo", "WANDSLInterfaceConfig#GetStatisticsTotal", "DeviceInfo#GetInfo"} {
		f.denied[k] = true
	}
	fb := fritzFor(t, f, f.pass)
	res := deRes(fb.Test(context.Background()))
	if !res.OK || res.Version != "154.08.02" || res.Summary != "FRITZ!Box 7590 · Zugang DSL" || !strings.Contains(res.Warning, "FRITZ!Box Einstellungen") {
		t.Errorf("Test: %+v", res)
	}
	svcs, err := fb.Collect(context.Background())
	var pe *PartialError
	if !errors.As(err, &pe) || !strings.Contains(deErr(err), "FRITZ!Box Einstellungen") {
		t.Fatalf("Teilfehler erwartet: %v", err)
	}
	if w := svcByKey(t, svcs, "wan"); w.Text != "DSL" || len(w.Facts) != 0 {
		t.Errorf("wan: %q %+v", w.Text, w.Facts)
	}
	if s := svcByKey(t, svcs, "system"); s.Text != "FRITZ!OS 154.08.02" {
		t.Errorf("system: %q", s.Text)
	}
	svcByKey(t, svcs, "updates")
	for _, s := range svcs {
		if s.Key == "dsl" {
			t.Error("DSL-Dienst ohne Recht")
		}
	}
}

func TestFritzboxTest(t *testing.T) {
	f := newFakeFritz()
	res := deRes(fritzFor(t, f, f.pass).Test(context.Background()))
	if !res.OK || res.Warning != "" || res.Summary != "FRITZ!Box 7590 · Zugang DSL" {
		t.Errorf("Test: %+v", res)
	}
	// falsches Kennwort: zwei Versuche (ohne und mit Aufforderung), dann Fehler mit Hinweis; das Kennwort steht nirgends
	f.mu.Lock()
	f.rejected = 0
	f.mu.Unlock()
	res = deRes(fritzFor(t, f, "falsch-falsch").Test(context.Background()))
	f.mu.Lock()
	rej := f.rejected
	f.mu.Unlock()
	if res.OK || !strings.Contains(res.Error, "FRITZ!Box-Benutzer und Kennwort prüfen") || strings.Contains(res.Error, "falsch-falsch") || rej != 2 {
		t.Errorf("falsches Kennwort: %+v, abgelehnt %d", res, rej)
	}
	// TR-064 ausgeschaltet
	f.mu.Lock()
	f.noDesc = true
	f.mu.Unlock()
	res = deRes(fritzFor(t, f, f.pass).Test(context.Background()))
	if res.OK || !strings.Contains(res.Error, "Zugriff für Anwendungen zulassen") {
		t.Errorf("ohne TR-064: %+v", res)
	}
	// ohne Pin: erst das Zertifikat bestaetigen, keine Anfrage mit Anmeldung
	f.mu.Lock()
	f.noDesc, f.rejected = false, 0
	f.mu.Unlock()
	addr, pin := tlsServer(t, f)
	np, err := NewFritzbox(FritzboxConfig{Address: addr, User: "monitor64", Password: f.pass})
	if err != nil {
		t.Fatal(err)
	}
	defer np.Close()
	r := np.Test(context.Background())
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.OK || !r.NeedConfirm || r.Fingerprint != pin || f.rejected != 0 {
		t.Errorf("ohne Pin: %+v, Anfragen %d", r, f.rejected)
	}
}

// Die FRITZ!Box verwirft die Aufforderung (z. B. nach einem Neustart): einmal neu anfordern, dann geht es weiter.
func TestFritzboxNonceRenew(t *testing.T) {
	f := newFakeFritz()
	fb := fritzFor(t, f, f.pass)
	if _, err := fb.Collect(context.Background()); err != nil {
		t.Fatal(deErr(err))
	}
	f.mu.Lock()
	f.nonce += 5 // alte Aufforderung gilt nicht mehr
	f.rejected = 0
	f.mu.Unlock()
	if _, err := fb.Collect(context.Background()); err != nil {
		t.Fatalf("nach verworfener Aufforderung: %v", deErr(err))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rejected != 1 {
		t.Errorf("abgelehnt %d", f.rejected)
	}
}

func TestFritzboxParsers(t *testing.T) {
	c, ok := parseFBChallenge(`Digest realm="HTTPS Access",nonce="ABC123",algorithm=MD5,qop="auth"`)
	if !ok || c.Realm != "HTTPS Access" || c.Nonce != "ABC123" || c.QOP != "auth" {
		t.Errorf("Aufforderung: %+v %v", c, ok)
	}
	for _, bad := range []string{"", "Basic realm=\"x\"", `Digest realm="x"`, `Digest realm="x", nonce="a", algorithm=SHA-256`} {
		if _, ok := parseFBChallenge(bad); ok {
			t.Errorf("%q angenommen", bad)
		}
	}
	d, err := parseFBDesc([]byte(fbDescXML("DeviceInfo", "WANDSLInterfaceConfig")))
	if err != nil || d.Model != "FRITZ!Box 7590" || d.Version != "154.08.02" || d.Ctrl[fbSvcDeviceInfo] != "/upnp/control/deviceinfo" || len(d.Ctrl) != 2 {
		t.Errorf("Beschreibung: %+v %v", d, err)
	}
	for _, c := range []FritzboxConfig{
		{Address: "https://fritz.box:49443", User: "", Password: "x"},
		{Address: "https://fritz.box:49443", User: "a\"b", Password: "x"},
		{Address: "https://fritz.box:49443", User: "monitor64", Password: ""},
		{Address: "http://fritz.box:49000", User: "monitor64", Password: "x"},
	} {
		if _, err := NewFritzbox(c); err == nil {
			t.Errorf("%+v angenommen", c)
		}
	}
	fb, err := NewFritzbox(FritzboxConfig{Address: "192.168.178.1", User: "monitor64", Password: "x"})
	if err != nil || fb.wc.t.base != "https://192.168.178.1:49443" {
		t.Errorf("Standard-Port: %v", err)
	}
}
