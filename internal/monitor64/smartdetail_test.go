package monitor64

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Bericht eines Agents (bzw. SSH): die Platte bekommt den Satz mit allen Werten; ohne Tabelle (Windows, aeltere
// Agents) die ausgewerteten Werte mit Hinweis; eine nicht lesbare Platte keinen.
func TestMapDisksSmartDetail(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }
	f := func(v float64) *float64 { return &v }
	out := MapReport(nil, &m64proto.Report{Time: 1700000000000, SMART: []m64proto.SMART{
		{Device: "/dev/sda", Type: "ata", Serial: "WD-1", Model: "WDC WD40EFRX", Firmware: "82.00A82", CapacityBytes: 4e12, Passed: bptr(true), ReadAt: 1699999000,
			Attrs: []m64proto.SMARTAttr{{ID: 5, Name: "Reallocated_Sector_Ct", Value: 200, Worst: 200, Thresh: 140, Raw: "0"}, {ID: 197, Name: "Current_Pending_Sector", Value: 1, Worst: 1, Raw: "8", Fail: "now"}}},
		{Device: "/dev/nvme0n1", Type: "nvme", Serial: "NV-1", Passed: bptr(true), Values: []m64proto.SMARTValue{{Key: "available_spare", Value: 100, Unit: "%"}}},
		{Device: "PhysicalDrive0", Type: "sata", Serial: "WIN-1", Passed: bptr(false), TempC: f(35), PowerOnHours: u(1234), Reallocated: u(2), CriticalWarning: u(4)},
		{Device: "/dev/sdx", Serial: "USB-1", Error: "nicht lesbar"},
	}})
	a := svcBy(out, "disk:WD-1")
	if a == nil || a.Smart == nil {
		t.Fatalf("ATA ohne Satz: %v", keysOf(out))
	}
	d := a.Smart
	if d.Model != "WDC WD40EFRX" || d.Serial != "WD-1" || d.Firmware != "82.00A82" || d.Size != 4e12 || d.Type != "ata" || d.Passed == nil || !*d.Passed ||
		!d.At.Equal(time.Unix(1699999000, 0)) || d.Partial || len(d.Attrs) != 2 || len(d.Values) != 0 {
		t.Fatalf("ATA: %+v", d)
	}
	if x := d.Attrs[1]; x.ID != 197 || *x.Value != 1 || *x.Thresh != 0 || x.Raw != "8" || x.Failed != "now" {
		t.Fatalf("Attribut: %+v", x)
	}
	n := svcBy(out, "disk:NV-1").Smart
	if n == nil || n.Partial || len(n.Values) != 1 || n.Values[0].Key != "available_spare" || !n.At.Equal(time.UnixMilli(1700000000000)) {
		t.Fatalf("NVMe: %+v", n)
	}
	w := svcBy(out, "disk:WIN-1").Smart
	if w == nil || !w.Partial || w.Passed == nil || *w.Passed {
		t.Fatalf("Windows: %+v", w)
	}
	got := map[string]float64{}
	for _, v := range w.Values {
		got[v.Key+"|"+v.Unit] = v.Value
	}
	if len(got) != 4 || got["temperature|°C"] != 35 || got["power_on_hours|h"] != 1234 || got["reallocated|"] != 2 || got["critical_warning|hex"] != 4 {
		t.Fatalf("Windows-Werte: %v", got)
	}
	if x := svcBy(out, "disk:USB-1"); x == nil || x.Smart != nil {
		t.Fatalf("nicht lesbare Platte: %+v", x)
	}
	// der Satz gehoert nicht zum gespeicherten bzw. verteilten Stand eines Dienstes
	if b, _ := json.Marshal(a); strings.Contains(string(b), "Reallocated_Sector_Ct") {
		t.Fatalf("Satz im JSON des Dienstes: %s", b)
	}
	// uebergrosse Angaben eines (fremden) Agents werden begrenzt
	big := m64proto.SMART{Device: "/dev/sdb", Serial: "BIG", Model: strings.Repeat("ä", 500)}
	for i := 0; i < 300; i++ {
		big.Attrs = append(big.Attrs, m64proto.SMARTAttr{ID: i, Raw: strings.Repeat("9", 400)})
	}
	bd := smartDetail(&big, 0)
	if len(bd.Attrs) != m64proto.MaxSmartRows || len(bd.Attrs[0].Raw) != maxSmartText || len(bd.Model) > maxSmartText || !strings.HasSuffix(bd.Model, "ä") || !bd.At.IsZero() {
		t.Fatalf("Begrenzung: %d Attribute, Raw %d, Modell %d", len(bd.Attrs), len(bd.Attrs[0].Raw), len(bd.Model))
	}
}

// Der Kern haelt je Dienst den letzten Satz: er bleibt, solange es den Dienst gibt, und verschwindet mit ihm.
func TestSmartStore(t *testing.T) {
	rt := &hostRT{}
	now := time.Unix(1700000000, 0)
	rt.setSmart(map[string]*model.SmartDetail{"disk:a": {Serial: "a"}, "disk:b": {Serial: "b", At: now.Add(-time.Hour)}}, map[string]bool{"disk:a": true, "disk:b": true}, now)
	if d := rt.smartOf("disk:a"); d == nil || !d.At.Equal(now) {
		t.Fatalf("Zeit der Abfrage fehlt: %+v", d)
	}
	if d := rt.smartOf("disk:b"); d == nil || !d.At.Equal(now.Add(-time.Hour)) {
		t.Fatalf("Zeit des Lesens ueberschrieben: %+v", d)
	}
	// Runde ohne Antwort des Zugangs: der Satz bleibt
	rt.setSmart(nil, map[string]bool{"disk:a": true, "disk:b": true}, now.Add(time.Minute))
	if rt.smartOf("disk:a") == nil || rt.smartOf("disk:b") == nil {
		t.Fatal("Satz nach einer Runde ohne Werte weg")
	}
	// Dienst entfernt: Satz weg
	rt.setSmart(nil, map[string]bool{"disk:a": true}, now.Add(2*time.Minute))
	if rt.smartOf("disk:a") == nil || rt.smartOf("disk:b") != nil {
		t.Fatal("Satz eines entfernten Dienstes bleibt")
	}
}

// GET /api/monitor64/hosts/{uid}/smart?key=: der Satz dieser Node, sonst 404; Anfrage einer anderen Node (Cluster).
func TestAPISmart(t *testing.T) {
	e := newEnv(t)
	rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "nas01", "address": "192.0.2.20", "kind": "pve", "paused": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &created)
	uid := created.UID
	path := "/api/monitor64/hosts/" + uid + "/smart?key=" + url.QueryEscape("disk:WD-1")
	if rec := e.do("GET", path, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("ohne Satz: %d %s", rec.Code, rec.Body)
	}
	e.m.rtMu.Lock()
	if e.m.rts == nil {
		e.m.rts = map[string]*hostRT{}
	}
	rt := e.m.rts[uid]
	if rt == nil {
		rt = &hostRT{host: &Host{UID: uid, Name: "nas01"}}
		e.m.rts[uid] = rt
	}
	e.m.rtMu.Unlock()
	v, th := 200, 140
	rt.setSmart(map[string]*model.SmartDetail{"disk:WD-1": {Type: "ata", Model: "WDC WD40EFRX", Serial: "WD-1", Passed: bptr(true),
		Attrs: []model.SmartAttr{{ID: 5, Name: "Reallocated_Sector_Ct", Value: &v, Thresh: &th, Raw: "0"}}}}, map[string]bool{"disk:WD-1": true}, time.Unix(1700000000, 0))
	rec = e.do("GET", path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mit Satz: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Key   string
		Smart model.SmartDetail
	}
	decodeBody(t, rec.Body.Bytes(), &out)
	if out.Key != "disk:WD-1" || out.Smart.Model != "WDC WD40EFRX" || len(out.Smart.Attrs) != 1 || *out.Smart.Attrs[0].Value != 200 || out.Smart.Attrs[0].Worst != nil ||
		!out.Smart.At.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("Antwort: %s", rec.Body)
	}
	for _, p := range []string{"/api/monitor64/hosts/" + uid + "/smart", "/api/monitor64/hosts/" + uid + "/smart?key=disk:x", "/api/monitor64/hosts/gibtsnicht/smart?key=disk:WD-1"} {
		if rec := e.do("GET", p, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	// Anfrage einer anderen Node
	body, _ := json.Marshal(smartReq{Host: uid, Key: "disk:WD-1"})
	res, err := e.m.handleSmartCall(body)
	if so, ok := res.(smartOut); err != nil || !ok || so.Smart == nil || so.Smart.Serial != "WD-1" {
		t.Fatalf("Cluster-Anfrage: %+v %v", res, err)
	}
	if res, err := e.m.handleSmartCall([]byte(`{"host":"` + uid + `","key":"disk:none"}`)); err != nil || res.(smartOut).Smart != nil {
		t.Fatalf("Cluster-Anfrage ohne Satz: %+v %v", res, err)
	}
	if _, err := e.m.handleSmartCall([]byte(`{"host":"../x","key":"a"}`)); err == nil {
		t.Fatal("ungueltige Cluster-Anfrage angenommen")
	}
}
