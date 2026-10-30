package healthchecks

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/proxmox"
	"github.com/ipv64net/node64/internal/scheduler"
)

// pveAddChannel legt einen Webhook-Kanal an (Kanalspeicher wird bei Bedarf eingerichtet).
func pveAddChannel(t *testing.T, m *Module, name string, def bool) int64 {
	t.Helper()
	ctx := context.Background()
	if m.notifyStore == nil {
		ms, _ := notify.Migrations()
		if err := m.core.Migrate(ctx, "notify", ms); err != nil {
			t.Fatal(err)
		}
		m.notifyStore = notify.NewStore(m.core, m.box)
	}
	c := &notify.Channel{Type: notify.TypeWebhook, Name: name, Config: map[string]string{"url": "http://x/", "method": "POST"}, Enabled: true, Default: def, NotifyDown: true, NotifyUp: true}
	if err := m.notifyStore.Insert(ctx, c); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func pveCheckOf(t *testing.T, m *Module, id int64, key string) *Check {
	t.Helper()
	set, _ := m.pve.st.Settings(context.Background(), id)
	it := set.Item(key)
	if it == nil || !it.AsCheck || it.CheckToken == "" {
		t.Fatalf("%s: not as check: %+v", key, it)
	}
	c, _ := m.st.Check(context.Background(), it.CheckToken)
	if c == nil {
		t.Fatalf("%s: check missing", key)
	}
	return c
}

// „als Check“: Kanaele aus den Proxmox-Regeln (auch nach Aenderung und Zuruecksetzen), schon gemeldete Stoerung
// geht ohne zweite Meldung an den Check (Entwarnung nur vom Check), pausiert bei abgeschaltetem System.
func TestPVEAsCheckChannelsHandOverPaused(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	m, srv, rec := newPVEModule(t, core, pveBox(t, 1))
	pveAddChannel(t, m, "std", true)
	b, c := pveAddChannel(t, m, "ops", false), pveAddChannel(t, m, "dev", false)
	id := pveCreate(t, srv, fsrv)
	base := "/api/healthchecks/proxmox/systems/" + fmt.Sprint(id) + "/settings"
	if code, body := call(t, srv, "PUT", base, map[string]any{"rules": map[string]any{"channels": []int64{b}}}); code != 200 {
		t.Fatalf("system channels: %d %s", code, body)
	}
	pvePollNow(t, m, id)
	rec.take()
	fake.set("qemu/101", "status", "stopped")
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 1 || al[0].Kind != notify.KindProxmoxDown || al[0].Check.Target != "qemu/101" {
		t.Fatalf("down: %s", pveKinds(al))
	}

	// als Check, waehrend die Stoerung gemeldet ist: Check beginnt gestoert, Kanaele wie die Regel
	if code, body := call(t, srv, "PUT", base+"?key=qemu/101", map[string]any{"as_check": true}); code != 200 {
		t.Fatalf("as_check: %d %s", code, body)
	}
	ck := pveCheckOf(t, m, id, "qemu/101")
	if !slices.Equal(ck.Channels, []int64{b}) || ck.Paused || ck.Runtime.State != scheduler.StateDown {
		t.Fatalf("check: channels %v paused %v state %s", ck.Channels, ck.Paused, ck.Runtime.State)
	}
	if rt, ok := m.scheduler().Runtime(ck.Token); !ok || rt.State != scheduler.StateDown || rt.DownSince.IsZero() {
		t.Fatalf("scheduler runtime: %+v %v", rt, ok)
	}
	fake.set("qemu/101", "status", "running")
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 0 {
		t.Fatalf("engine reported for as check: %s", pveKinds(al))
	}

	// Regeln geaendert bzw. zurueckgesetzt: Kanaele des Checks folgen
	call(t, srv, "PUT", base, map[string]any{"rules": map[string]any{"channels": []int64{c}}})
	if ck = pveCheckOf(t, m, id, "qemu/101"); !slices.Equal(ck.Channels, []int64{c}) {
		t.Fatalf("after system rule: %v", ck.Channels)
	}
	call(t, srv, "PUT", base+"?key=qemu/101", map[string]any{"rules": map[string]any{"channels": []int64{b}}})
	if ck = pveCheckOf(t, m, id, "qemu/101"); !slices.Equal(ck.Channels, []int64{b}) {
		t.Fatalf("after guest rule: %v", ck.Channels)
	}
	if code, _ := call(t, srv, "DELETE", base+"?key=qemu/101", nil); code != 204 {
		t.Fatal("reset")
	}
	if ck = pveCheckOf(t, m, id, "qemu/101"); !slices.Equal(ck.Channels, []int64{c}) { // Zuruecksetzen behaelt „als Check“
		t.Fatalf("after reset: %v", ck.Channels)
	}
	resp, _ := pvePost(t, srv, pveResPath(id, "")+"/settings", map[string][]string{"key": {""}, "op": {"save"}})
	if ck = pveCheckOf(t, m, id, "qemu/101"); resp.StatusCode != 303 || ck.Channels != nil {
		t.Fatalf("form default channels: %v", ck.Channels)
	}
	// Check-Formular: Kanaele nur angezeigt (Standardkanaele mit Namen), Speichern laesst sie unveraendert
	if code, page := pveGet(t, srv, "/healthchecks/"+ck.Token+"/edit"); code != 200 || !strings.Contains(page, "data-sys-channels") || !strings.Contains(page, "std") ||
		!strings.Contains(page, pveResPath(id, "qemu/101")+"#rules") || strings.Contains(page, `name="channels"`) {
		t.Fatalf("edit form: %d %s", code, page)
	}
	resp, _ = pvePost(t, srv, "/healthchecks/"+ck.Token+"/edit", map[string][]string{"name": {ck.Name}, "type": {"proxmox"}, "pve_params": {string(ck.Params)},
		"interval_seconds": {"60"}, "retry_interval_seconds": {"20"}, "retries": {"1"}, "stabilize": {"3"}, "connect_timeout_seconds": {"5"},
		"timeout_seconds": {"10"}, "notify_down": {"on"}, "channels": {fmt.Sprint(b)}})
	if ck = pveCheckOf(t, m, id, "qemu/101"); resp.StatusCode != 303 || ck.Channels != nil {
		t.Fatalf("edit keeps rule channels: %d %v", resp.StatusCode, ck.Channels)
	}

	// System abgeschaltet: neuer Check pausiert
	if code, _ := call(t, srv, "PUT", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id), map[string]any{"enabled": false}); code != 200 {
		t.Fatal("disable")
	}
	if code, body := call(t, srv, "PUT", base+"?key=lxc/200", map[string]any{"as_check": true}); code != 200 {
		t.Fatalf("as_check disabled: %d %s", code, body)
	}
	if ck = pveCheckOf(t, m, id, "lxc/200"); !ck.Paused {
		t.Fatal("check of a disabled system not paused")
	}
}

// „als Check“ aus, waehrend der Check gestoert ist: die Engine uebernimmt die Stoerung (keine zweite Meldung) und
// meldet die Entwarnung.
func TestPVEAsCheckOffAdopts(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	m, srv, rec := newPVEModule(t, core, pveBox(t, 1))
	id := pveCreate(t, srv, fsrv)
	base := "/api/healthchecks/proxmox/systems/" + fmt.Sprint(id) + "/settings?key=qemu/101"
	pvePollNow(t, m, id)
	call(t, srv, "PUT", base, map[string]any{"as_check": true})
	ck := pveCheckOf(t, m, id, "qemu/101")
	fake.set("qemu/101", "status", "stopped")
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	rec.take()
	// der Check hat die Stoerung gemeldet
	upsertSched(m.scheduler(), ck, &scheduler.Runtime{State: scheduler.StateDown, Since: time.Now(), DownSince: time.Now(), LastStatus: "down"})
	call(t, srv, "PUT", base, map[string]any{"as_check": false})
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 0 {
		t.Fatalf("reported again: %s", pveKinds(al))
	}
	fake.set("qemu/101", "status", "running")
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 1 || al[0].Kind != notify.KindProxmoxUp || al[0].Check.Target != "qemu/101" {
		t.Fatalf("up: %s", pveKinds(al))
	}
}

// Vor dem ersten Stand liefert pveLookup den Start der Abfrage (der Check bleibt dann beim vorigen Ergebnis).
func TestPVELookupPending(t *testing.T) {
	fsrv := startPVEFake(t, newPVEFake())
	m, srv, _ := newPVEModule(t, pveCore(t), pveBox(t, 1))
	id := pveCreate(t, srv, fsrv)
	st := m.pveLookup(id, "qemu/100")
	if !st.Polling || !st.Time.IsZero() || st.Started.IsZero() || time.Since(st.Started) > time.Minute {
		t.Fatalf("lookup: %+v", st)
	}
}

// Import: abgeschaltetes System wird angehalten (Stand verworfen, Checks pausiert); gleichnamige Systeme werden ueber
// die Adressen zugeordnet, mehrdeutige Namen bzw. mehrere Eintraege fuer dasselbe System legen neu an.
func TestPVEImportDisableAndNames(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	m, srv, _ := newPVEModule(t, core, pveBox(t, 1))
	ctx := context.Background()
	create := func(name, addr string) int64 {
		code, b := call(t, srv, "POST", "/api/healthchecks/proxmox/systems", map[string]any{"name": name, "addresses": []string{addr},
			"token_id": pveTestToken, "secret": pveTestSecret, "pin_sha256": pvePinOf(fsrv)})
		if code != 201 {
			t.Fatalf("create: %d %s", code, b)
		}
		list, _ := m.pve.st.Systems(ctx)
		return list[len(list)-1].ID
	}
	a := create("pve", fsrv.URL)
	other := create("pve", "https://pve-b.example:8006")
	if a == other {
		t.Fatal("ids")
	}
	pvePollNow(t, m, a) // Absturz qemu/102 gemeldet: Stand der Engine gespeichert
	call(t, srv, "PUT", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(a)+"/settings?key=qemu/100", map[string]any{"as_check": true})
	if core.SettingOr(ctx, pveSettingEngine+fmt.Sprint(a), "") == "" {
		t.Fatal("no engine state")
	}
	in := []pveExportSystem{{Name: "PVE", Addresses: []string{fsrv.URL}, TokenID: pveTestToken, PinSHA256: pvePinOf(fsrv), Interval: 30, Enabled: false}}
	if _, err := m.pveImport(ctx, in); err != nil {
		t.Fatal(err)
	}
	if sys, _ := m.pve.st.System(ctx, a); sys.Enabled || sys.Secret != pveTestSecret {
		t.Fatalf("not matched by address: %+v", sys)
	}
	if pp, _ := m.pvePollOf(a); pp != nil {
		t.Fatal("still polled after import with enabled=false")
	}
	if raw := core.SettingOr(ctx, pveSettingEngine+fmt.Sprint(a), ""); raw != "" {
		t.Fatalf("engine state kept: %s", raw)
	}
	if ck := pveCheckOf(t, m, a, "qemu/100"); !ck.Paused {
		t.Fatal("check not paused")
	}
	if pp, _ := m.pvePollOf(other); pp == nil {
		t.Fatal("other system touched")
	}
	// zwei Eintraege fuer dasselbe System bzw. Name ohne passende Adresse: neu anlegen
	in = []pveExportSystem{
		{Name: "pve", Addresses: []string{"https://pve-b.example:8006"}, TokenID: pveTestToken, Interval: 30},
		{Name: "pve", Addresses: []string{"https://pve-b.example:8006"}, TokenID: pveTestToken, Interval: 30},
		{Name: "pve", Addresses: []string{"https://pve-c.example:8006"}, TokenID: pveTestToken, Interval: 30},
	}
	_, _ = m.pveImport(ctx, in) // ohne Secret: Hinweis als Fehler
	if list, _ := m.pve.st.Systems(ctx); len(list) != 5 {
		t.Fatalf("systems: %d", len(list))
	}
	if sys, _ := m.pve.st.System(ctx, other); !sys.Enabled {
		t.Fatal("ambiguous import merged into an existing system")
	}
}

// Gleichzeitiges Speichern: keine verwaiste Abfrage (Stop kehrt zurueck, genau eine Abfrage je System).
func TestPVERunConcurrent(t *testing.T) {
	fsrv := startPVEFake(t, newPVEFake())
	m, srv, _ := newPVEModule(t, pveCore(t), pveBox(t, 1))
	id := pveCreate(t, srv, fsrv)
	sys, _ := m.pve.st.System(context.Background(), id)
	m.pve.mu.Lock()
	m.pve.noRun = false
	m.pve.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.pveRun(context.Background(), sys)
		}()
	}
	wg.Wait()
	m.pve.mu.Lock()
	n := len(m.pve.polls)
	m.pve.mu.Unlock()
	if n != 1 {
		t.Fatalf("polls: %d", n)
	}
	done := make(chan struct{})
	go func() { m.pveStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("orphaned poller: stop does not return")
	}
}

// CPU-Linien der Systemseite: Index (system_id, t) statt Lauf ueber 48 h aller Gaeste.
func TestPVESparkIndex(t *testing.T) {
	core := pveCore(t)
	newPVEModule(t, core, pveBox(t, 1))
	rows, err := core.Reader().Query(`EXPLAIN QUERY PLAN SELECT key, t, cpu FROM pve_hist_1m WHERE system_id = ? AND t >= ? ORDER BY t`, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var a, b, c int
		var d string
		if err := rows.Scan(&a, &b, &c, &d); err == nil {
			plan = append(plan, d)
		}
	}
	if !strings.Contains(strings.Join(plan, " | "), "pve_hist_1m_sys_t") {
		t.Fatalf("plan: %v", plan)
	}
}

// Systemseite: Filter-Auswahl sendet selbst ab (app.js, data-autosubmit am Feld), Raten mit $.Bytes (Locale).
func TestPVEPageFilterAndRates(t *testing.T) {
	fsrv := startPVEFake(t, newPVEFake())
	m, srv, _ := newPVEModule(t, pveCore(t), pveBox(t, 1))
	id := pveCreate(t, srv, fsrv)
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	_, body := pveGet(t, srv, pveResPath(id, ""))
	if !strings.Contains(body, `name="state" data-autosubmit`) || !strings.Contains(body, `name="type" data-autosubmit`) || strings.Contains(body, `align-items-end" data-autosubmit`) ||
		!strings.Contains(body, "↓ 0B/s · ↑ 0B/s") {
		t.Fatalf("system page: %s", body)
	}
	if _, body = pveGet(t, srv, pveResPath(id, "qemu/100")); !strings.Contains(body, "R 0B/s · W 0B/s") {
		t.Fatalf("guest page: %s", body)
	}
	// gestoerter System-Zustand nur bei eigenem Problem (Karte)
	if row := m.pveSysView(context.Background(), &proxmox.System{ID: id, Enabled: true}); row.State != "warn" || row.SysProblem {
		t.Fatalf("row: %s %v", row.State, row.SysProblem)
	}
}

// „Gestoppt ist richtig“: Knopf an der gestoerten Zeile, Stoerung erledigt sich still, letzte Stoerung weg.
func TestPVEAckStopped(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	m, srv, rec := newPVEModule(t, pveCore(t), pveBox(t, 1))
	ctx := context.Background()
	id := pveCreate(t, srv, fsrv)
	sp := pveResPath(id, "")
	pvePollNow(t, m, id) // db (qemu/101) laeuft: „lief schon einmal“
	fake.set("qemu/101", "status", "stopped")
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	down := false
	for _, a := range rec.take() {
		if a.Kind == notify.KindProxmoxDown && a.Check.Target == "qemu/101" {
			down = true
		}
	}
	if !down {
		t.Fatal("keine Meldung „gestoppt“")
	}
	if inc := m.pveLastIncident(ctx); inc == nil || inc.Key != "qemu/101" {
		t.Fatalf("letzte Stoerung: %+v", inc)
	}
	ackForm := `name="key" value="qemu/101"><input type="hidden" name="back" value="` + sp + `"><button class="btn btn-sm btn-outline-secondary py-0"`
	_, body := pveGet(t, srv, sp)
	if !strings.Contains(body, `action="`+sp+`/ack"`) || !strings.Contains(body, ackForm) || !strings.Contains(body, "pve.ack.btn") {
		t.Fatalf("Knopf fehlt: %s", body)
	}
	if _, body = pveGet(t, srv, pveResPath(id, "qemu/101")); !strings.Contains(body, "pve.ack.hint") {
		t.Fatalf("Gastseite ohne Hinweis: %s", body)
	}
	// Gaeste und Nodes (Wartung), nicht das System
	if resp, _ := pvePost(t, srv, sp+"/ack", url.Values{"key": {""}}); resp.StatusCode != 400 {
		t.Fatalf("System: %d", resp.StatusCode)
	}
	if resp, _ := pvePost(t, srv, sp+"/ack", url.Values{"key": {"node/pve1"}, "back": {sp}}); resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("X-Flash"), "success:pve.ack_node.done") {
		t.Fatalf("Node: %d %v", resp.StatusCode, resp.Header)
	}
	if set, _ := m.pve.st.Settings(context.Background(), id); set.Item("node/pve1").ExpectRunning == nil || *set.Item("node/pve1").ExpectRunning {
		t.Fatalf("Node: %+v", set.Item("node/pve1"))
	}
	pvePollNow(t, m, id) // Node ist online: Wartung vorbei, Markierung faellt weg
	if set, _ := m.pve.st.Settings(context.Background(), id); set.Item("node/pve1").ExpectRunning != nil {
		t.Fatalf("Node online, Markierung bleibt: %+v", set.Item("node/pve1"))
	}
	pvePost(t, srv, sp+"/ack", url.Values{"key": {"node/pve1"}})
	if resp, _ := pvePost(t, srv, sp+"/ack", url.Values{"key": {"node/pve1"}, "undo": {"1"}, "back": {sp}}); resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("X-Flash"), "success:pve.ack_node.undone") {
		t.Fatalf("Node undo: %d %v", resp.StatusCode, resp.Header)
	}
	if set, _ := m.pve.st.Settings(context.Background(), id); set.Item("node/pve1").ExpectRunning != nil {
		t.Fatalf("Node undo: %+v", set.Item("node/pve1"))
	}
	resp, _ := pvePost(t, srv, sp+"/ack", url.Values{"key": {"qemu/101"}, "back": {sp}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != sp || !strings.Contains(resp.Header.Get("X-Flash"), "success:pve.ack.done") {
		t.Fatalf("ack: %d %v", resp.StatusCode, resp.Header)
	}
	set, _ := m.pve.st.Settings(ctx, id)
	if it := set.Item("qemu/101"); it == nil || it.ExpectRunning == nil || *it.ExpectRunning {
		t.Fatalf("ExpectRunning: %+v", it)
	}
	if inc := m.pveLastIncident(ctx); inc != nil {
		t.Fatalf("letzte Stoerung noch da: %+v", inc)
	}
	rec.mu.Lock()
	audited := slices.Contains(rec.audit, "proxmox.ack lab / qemu/101")
	rec.mu.Unlock()
	if !audited {
		t.Fatalf("Audit: %v", rec.audit)
	}
	_, body = pveGet(t, srv, sp)
	if strings.Contains(body, ackForm) || !strings.Contains(body, "pve.ack.off_title") {
		t.Fatalf("nach ack: %s", body)
	}
	if _, body = pveGet(t, srv, pveResPath(id, "qemu/101")); !strings.Contains(body, "pve.ack.active_hint") || strings.Contains(body, "pve.ack.hint") {
		t.Fatalf("Gastseite nach ack: %s", body)
	}
	// still erledigt: keine Entwarnung, auch nicht, wenn er spaeter wieder laeuft
	pvePollNow(t, m, id)
	if _, ok := m.pve.engine.Outage(id, "qemu/101"); ok {
		t.Fatal("Stoerung noch offen")
	}
	fake.set("qemu/101", "status", "running")
	pvePollNow(t, m, id)
	for _, a := range rec.take() {
		if a.Check.Target == "qemu/101" {
			t.Fatalf("Meldung nach ack: %+v", a)
		}
	}
}
