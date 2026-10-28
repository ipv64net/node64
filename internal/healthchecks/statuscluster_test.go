package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/proxmox"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/wire"
)

// hcChange ist eine Meldung an den Cluster (Hook ClusterHooks.Change).
type hcChange struct {
	item, id string
	deleted  bool
}

type hcLog struct {
	mu    sync.Mutex
	calls []hcChange
}

func (l *hcLog) hook(_ context.Context, item, id string, deleted bool) {
	l.mu.Lock()
	l.calls = append(l.calls, hcChange{item, id, deleted})
	l.mu.Unlock()
}

func (l *hcLog) take() []hcChange {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.calls
	l.calls = nil
	return out
}

// hcTransfer uebertraegt die gemeldeten Eintraege von a nach b (wie der Cluster: Stand holen, uebernehmen).
func hcTransfer(t *testing.T, a, b *Module, calls []hcChange) {
	t.Helper()
	ctx := context.Background()
	for _, c := range calls {
		data, found, err := a.ClusterGet(ctx, c.item, c.id)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ClusterApply(ctx, c.item, c.id, data, c.deleted || !found); err != nil {
			t.Fatalf("apply %+v: %v", c, err)
		}
	}
}

func pageCount(t *testing.T, m *Module) int {
	t.Helper()
	list, err := m.st.StatusPages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(list)
}

// Statusseiten ueber den Cluster: Seite samt Gruppen, Checks (Token), Logo, Passwort und Ankuendigungen; Aendern,
// Loeschen, gleicher Slug mit anderem Inhalt wird nicht uebernommen.
func TestStatusPageClusterSync(t *testing.T) {
	ctx := context.Background()
	a, _ := newTestModule(t)
	b, _ := newTestModule(t)
	var la, lb hcLog
	a.SetCluster(ClusterHooks{Change: la.hook})
	b.SetCluster(ClusterHooks{Change: lb.hook})

	p := &StatusPage{Slug: "home", Title: "Zuhause", Description: "Alles da", Enabled: true, PublishNode: true, Layout: "tiles", Days: 60, ShowUptime: true,
		Groups: []StatusGroup{
			{Name: "Web", Items: []StatusItem{{Token: "tok_web_0123456789", Label: "Webseite"}, {Token: "tok_nas_0123456789"}}},
			{Name: "Intern", Items: []StatusItem{{Token: "tok_dns_0123456789"}}},
		}}
	if err := a.st.SaveStatusPage(ctx, p, "$2a$10$abcdefghijklmnopqrstuuJ8m3B6v8m7l1aZ0lE0yQnP4v0b2s5e"); err != nil {
		t.Fatal(err)
	}
	if !statusUIDRe.MatchString(p.UID) {
		t.Fatalf("uid: %q", p.UID)
	}
	if _, err := a.st.AddStatusNotice(ctx, p.ID, "Wartung", "warning", "Heute Abend"); err != nil {
		t.Fatal(err)
	}
	if err := a.st.SetStatusLogo(ctx, p.ID, []byte("\x89PNG fake"), "image/png"); err != nil {
		t.Fatal(err)
	}
	calls := la.take()
	if len(calls) != 3 || calls[0] != (hcChange{ClusterItemStatusPages, p.UID, false}) {
		t.Fatalf("hook: %+v", calls)
	}
	if ids, _ := a.ClusterIDs(ctx, ClusterItemStatusPages); len(ids) != 1 || ids[0] != p.UID {
		t.Fatalf("ids: %v", ids)
	}
	_ = b.st.SaveStatusPage(ctx, &StatusPage{Slug: "vorher", Title: "Vorher auf B"}, "") // andere lokale Nummer auf B
	lb.take()
	hcTransfer(t, a, b, calls)

	got, err := b.st.StatusPageBySlug(ctx, "home")
	if err != nil || got.UID != p.UID || got.ID == p.ID || got.Title != "Zuhause" || got.Layout != "tiles" || got.Days != 60 || !got.PublishNode {
		t.Fatalf("page on B: %+v %v", got, err)
	}
	if len(got.Groups) != 2 || len(got.Groups[0].Items) != 2 || got.Groups[0].Items[0].Token != "tok_web_0123456789" ||
		got.Groups[0].Items[0].Label != "Webseite" || got.Groups[1].Items[0].Token != "tok_dns_0123456789" {
		t.Fatalf("groups on B: %+v", got.Groups)
	}
	if b.st.statusPasswordHash(ctx, got.ID) != a.st.statusPasswordHash(ctx, p.ID) {
		t.Fatal("password hash must be the same")
	}
	if logo, ct, _, _ := b.st.StatusLogo(ctx, got.ID); !bytes.Equal(logo, []byte("\x89PNG fake")) || ct != "image/png" {
		t.Fatalf("logo on B: %q %s", logo, ct)
	}
	if n, _ := b.st.StatusNotices(ctx, got.ID, time.Time{}); len(n) != 1 || n[0].Title != "Wartung" || len(n[0].Updates) != 1 || n[0].Updates[0].Text != "Heute Abend" {
		t.Fatalf("notices on B: %+v", n)
	}
	if c := lb.take(); len(c) == 0 || c[0].id != p.UID {
		t.Fatalf("B must report the applied page with the same uid: %+v", c)
	}

	// Aenderung auf B (Titel, Reihenfolge) kommt bei A an; Loeschen auf A kommt bei B an
	got.Title = "Neu"
	got.Groups[0], got.Groups[1] = got.Groups[1], got.Groups[0]
	if err := b.st.SaveStatusPage(ctx, got, ""); err != nil {
		t.Fatal(err)
	}
	hcTransfer(t, b, a, lb.take())
	if ap, _ := a.st.StatusPage(ctx, p.ID); ap.Title != "Neu" || ap.Groups[0].Name != "Intern" || ap.UID != p.UID {
		t.Fatalf("update on A: %+v", ap)
	}
	if err := a.st.DeleteStatusPage(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	hcTransfer(t, a, b, la.take())
	if _, err := b.st.StatusPageBySlug(ctx, "home"); !errors.Is(err, ErrStatusPageNotFound) {
		t.Fatalf("delete must reach B: %v", err)
	}

	// gleicher Slug, anderer Inhalt: nicht uebernehmen
	_ = a.st.SaveStatusPage(ctx, &StatusPage{Slug: "vorher", Title: "Anders auf A"}, "")
	data, _, _ := a.ClusterGet(ctx, ClusterItemStatusPages, la.take()[0].id)
	if err := b.ClusterApply(ctx, ClusterItemStatusPages, strings.Repeat("c", 32), data, false); !errors.Is(err, errStatusSlug) {
		t.Fatalf("slug conflict: %v", err)
	}
	if bp, _ := b.st.StatusPageBySlug(ctx, "vorher"); bp.Title != "Vorher auf B" {
		t.Fatal("page on B must stay")
	}
}

// Exaktes Doppel (auf beiden Nodes vor dem Cluster gleich angelegt): beide landen bei der kleineren Kennung, die
// lokale Nummer bleibt.
func TestStatusPageClusterDuplicate(t *testing.T) {
	ctx := context.Background()
	a, _ := newTestModule(t)
	b, _ := newTestModule(t)
	var la, lb hcLog
	a.SetCluster(ClusterHooks{Change: la.hook})
	b.SetCluster(ClusterHooks{Change: lb.hook})
	uidA, uidB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	page := func(uid string) *StatusPage {
		return &StatusPage{Slug: "dienste", Title: "Dienste", Enabled: true, UID: uid,
			Groups: []StatusGroup{{Name: "Alle", Items: []StatusItem{{Token: "tok_web_0123456789"}}}}}
	}
	_ = b.st.SaveStatusPage(ctx, &StatusPage{Slug: "platz", Title: "andere Nummer"}, "")
	pa, pb := page(uidA), page(uidB)
	if err := a.st.SaveStatusPage(ctx, pa, ""); err != nil {
		t.Fatal(err)
	}
	if err := b.st.SaveStatusPage(ctx, pb, ""); err != nil {
		t.Fatal(err)
	}
	ca, cb := la.take(), lb.take()
	hcTransfer(t, a, b, ca) // B: fremde Kennung kleiner -> uebernimmt sie, meldet die alte als geloescht
	hcTransfer(t, b, a, cb) // A: eigene Kennung kleiner -> bleibt (B's alte Kennung gibt es dort nicht mehr)
	callsB := lb.take()
	if !slices.Contains(callsB, hcChange{ClusterItemStatusPages, uidB, true}) {
		t.Fatalf("B must report its old uid as deleted: %+v", callsB)
	}
	hcTransfer(t, b, a, callsB)
	hcTransfer(t, a, b, la.take())
	for _, m := range []*Module{a, b} {
		got, err := m.st.StatusPageBySlug(ctx, "dienste")
		if err != nil || got.UID != uidA {
			t.Fatalf("page: %+v %v", got, err)
		}
	}
	if pageCount(t, a) != 2 || pageCount(t, b) != 2 { // dazu die andere Seite von B
		t.Fatalf("pages: A %d B %d", pageCount(t, a), pageCount(t, b))
	}
	if got, _ := b.st.StatusPageBySlug(ctx, "dienste"); got.ID != pb.ID {
		t.Fatal("local number on B must stay (PROXY64 hosts point to it)")
	}
}

// Wartungsfenster, auf zwei Nodes gleich angelegt: das mit der kleineren Kennung bleibt, das andere geht mit
// Loeschvermerk; nur aehnliche Fenster bleiben beide.
func TestMaintenanceClusterDuplicate(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestModule(t)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	local := &Maintenance{UID: strings.Repeat("5", 24), Name: "Update", StartAt: start, EndAt: start.Add(time.Hour), Repeat: "none", Tokens: []string{"t2", "t1"}, Active: true}
	if err := m.st.MaintenanceInsert(ctx, local); err != nil {
		t.Fatal(err)
	}
	win := func(uid, name string) PeerMaint {
		return PeerMaint{UID: uid, Maintenance: wire.Maintenance{Name: name, StartAt: start, EndAt: start.Add(time.Hour), Repeat: "none", Tokens: []string{"t1", "t2"}, Active: true}}
	}
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	// groessere fremde Kennung: hier bleibt das eigene Fenster, das fremde wird nicht angelegt
	if _, ok, err := m.ApplyPeerMaintenance(ctx, win(strings.Repeat("9", 24), "Update"), t0, "node-b"); ok || err != nil {
		t.Fatalf("bigger uid: %v %v", ok, err)
	}
	// aehnlich, aber anderer Name: kein Doppel
	if _, ok, _ := m.ApplyPeerMaintenance(ctx, win(strings.Repeat("6", 24), "Update 2"), t0, "node-b"); !ok {
		t.Fatal("similar window must be applied")
	}
	// kleinere fremde Kennung: das eigene geht (Loeschvermerk), das fremde kommt
	if _, ok, err := m.ApplyPeerMaintenance(ctx, win(strings.Repeat("1", 24), "Update"), t0, "node-b"); !ok || err != nil {
		t.Fatalf("smaller uid: %v %v", ok, err)
	}
	uids := m.PeerMaintUIDs(ctx)
	slices.Sort(uids)
	if !slices.Equal(uids, []string{strings.Repeat("1", 24), strings.Repeat("6", 24)}) {
		t.Fatalf("windows: %v", uids)
	}
	if _, _, del, _, _ := m.PeerMaintenance(ctx, local.UID); del.IsZero() {
		t.Fatal("merged window needs a tombstone")
	}
}

// Docker-Host auf zwei Nodes gleich angelegt: beide landen bei der kleineren Kennung, die lokale Nummer bleibt.
func TestDockerClusterDuplicate(t *testing.T) {
	ctx := context.Background()
	coreA, coreB := pveCore(t), pveCore(t)
	mA, _, _ := newPVEModule(t, coreA, pveBox(t, 1))
	mB, _, _ := newPVEModule(t, coreB, pveBox(t, 2))
	var la, lb hcLog
	mA.SetCluster(ClusterHooks{Change: la.hook})
	mB.SetCluster(ClusterHooks{Change: lb.hook})
	const nodeA, nodeB = "nodeA_0123456789abcdef", "nodeB_0123456789abcdef"
	uidA, uidB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	host := func(uid string) *proxmox.System {
		return &proxmox.System{Kind: proxmox.KindDocker, Name: "nas", Addresses: []string{"tcp://192.0.2.7:2375"}, Interval: 30, Enabled: true, UID: uid}
	}
	setSelfID(t, nodeA)
	if err := mA.pveSaveSystemBy(ctx, host(uidA), "test"); err != nil {
		t.Fatal(err)
	}
	setSelfID(t, nodeB)
	_ = mB.pveSaveSystemBy(ctx, &proxmox.System{Kind: proxmox.KindDocker, Name: "andere", Addresses: []string{"tcp://192.0.2.9:2375"}, Interval: 30, Enabled: true}, "test")
	sb := host(uidB)
	if err := mB.pveSaveSystemBy(ctx, sb, "test"); err != nil {
		t.Fatal(err)
	}
	ca, cb := la.take(), lb.take()
	setSelfID(t, nodeB)
	hcTransfer(t, mA, mB, ca)
	setSelfID(t, nodeA)
	hcTransfer(t, mB, mA, cb)
	callsB := lb.take()
	if !slices.Contains(callsB, hcChange{ClusterItemDocker, uidB, true}) {
		t.Fatalf("B must report its old uid as deleted: %+v", callsB)
	}
	hcTransfer(t, mB, mA, callsB)
	for _, m := range []*Module{mA, mB} {
		ids, _ := m.ClusterIDs(ctx, ClusterItemDocker)
		if !slices.Contains(ids, uidA) || slices.Contains(ids, uidB) {
			t.Fatalf("docker ids: %v", ids)
		}
	}
	if len(mustIDs(t, mA)) != 2 || len(mustIDs(t, mB)) != 2 { // dazu der andere Host von B
		t.Fatal("no duplicate systems")
	}
	if got, err := mB.pve.st.SystemByUID(ctx, uidA); err != nil || got.ID != sb.ID { // Heim-Node: im Test teilen sich beide die eigene Kennung
		t.Fatalf("B keeps its local system under the new uid: %+v %v", got, err)
	}
}

func mustIDs(t *testing.T, m *Module) []string {
	t.Helper()
	ids, err := m.ClusterIDs(context.Background(), ClusterItemDocker)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// nfModule: Healthchecks mit Kanalspeicher (Zuordnung Check -> Kanal ueber den Cluster).
func nfModule(t *testing.T) (*Module, *notify.Store, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	nm, _ := notify.Migrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	if err := core.Migrate(context.Background(), "notify", nm); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.Load(filepath.Join(dir, "secret.key"))
	nf := notify.NewStore(core, box)
	m := New(core, log, nil, nf, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Stop(context.Background()) })
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return m, nf, srv
}

// Zuordnung Check -> Kanal im Cluster: ueber die Kennung des Kanals (lokale Nummern verschieden), Kanaele ausserhalb
// des Clusters (Portal) bleiben; gleicher Stand vereint beide Seiten; ohne Kennungen bleibt alles je Node.
func TestPeerCheckChannelUIDs(t *testing.T) {
	ctx := context.Background()
	a, nfA, srvA := nfModule(t)
	b, nfB, _ := nfModule(t)
	tg := func(uid string) *notify.Channel {
		return &notify.Channel{Type: notify.TypeTelegram, Name: "tg", Config: map[string]string{"bot_token": "1:A", "chat_id": "1"}, Enabled: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "node", UID: uid}
	}
	uid := strings.Repeat("c", 32)
	chA := tg(uid)
	if err := nfA.Insert(ctx, chA); err != nil {
		t.Fatal(err)
	}
	_ = nfB.Insert(ctx, tg(strings.Repeat("d", 32))) // andere lokale Nummer auf B
	chB := tg(uid)
	_ = nfB.Insert(ctx, chB)
	portal := &notify.Channel{Type: notify.TypeIPv64Mail, Name: "Portal", Config: map[string]string{}, Enabled: true, Execution: "server", RemoteID: 7}
	_ = nfB.Insert(ctx, portal)
	if chA.ID == chB.ID {
		t.Fatal("test needs different local numbers")
	}
	code, body := call(t, srvA, "POST", "/api/checks", map[string]any{"name": "web", "type": "icmp", "target": "192.0.2.1", "interval_seconds": 60, "channels": []int64{chA.ID}})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, body)
	}
	var cr struct{ Token string }
	_ = json.Unmarshal(body, &cr)
	w, upd, _, err := a.PeerCheck(ctx, cr.Token, "node-a")
	if err != nil || w.ChannelUIDs == nil || !slices.Equal(*w.ChannelUIDs, []string{uid}) {
		t.Fatalf("channel uids on A: %+v %v", w, err)
	}
	t1 := upd.Add(time.Second)
	if ok, err := b.ApplyPeerCheck(ctx, *w, t1, "node-a", "node-b"); !ok || err != nil {
		t.Fatalf("apply: %v %v", ok, err)
	}
	cb, _ := b.st.Check(ctx, cr.Token)
	if !slices.Equal(cb.Channels, []int64{chB.ID}) {
		t.Fatalf("channels on B: %v (want %d)", cb.Channels, chB.ID)
	}
	// Portal-Kanal hier zugeordnet; A nimmt den Kanal heraus -> Portal-Kanal bleibt
	_, _ = b.st.w.ExecContext(ctx, `UPDATE hc_checks SET channels = ? WHERE token = ?`, joinInts([]int64{chB.ID, portal.ID}), cr.Token)
	w.ChannelUIDs = &[]string{}
	t2 := t1.Add(time.Second)
	if ok, _ := b.ApplyPeerCheck(ctx, *w, t2, "node-a", "node-b"); !ok {
		t.Fatal("newer change must apply")
	}
	if cb, _ = b.st.Check(ctx, cr.Token); !slices.Equal(cb.Channels, []int64{portal.ID}) {
		t.Fatalf("portal channel must stay: %v", cb.Channels)
	}
	// gleicher Stand mit Kennungen (Bereich gerade eingeschaltet): vereinen, ohne neue Aenderung
	w.ChannelUIDs = &[]string{uid}
	if ok, _ := b.ApplyPeerCheck(ctx, *w, cb.UpdatedAt, "node-a", "node-b"); ok {
		t.Fatal("same state is no change")
	}
	if cb2, _ := b.st.Check(ctx, cr.Token); !slices.Equal(cb2.Channels, []int64{portal.ID, chB.ID}) || !cb2.UpdatedAt.Equal(cb.UpdatedAt) {
		t.Fatalf("union: %v", cb2.Channels)
	}
	// ohne Kennungen (Bereich aus): Kanaele bleiben je Node
	w.ChannelUIDs = nil
	if ok, _ := b.ApplyPeerCheck(ctx, *w, t2.Add(time.Second), "node-a", "node-b"); !ok {
		t.Fatal("newer change must apply")
	}
	if cb, _ = b.st.Check(ctx, cr.Token); !slices.Equal(cb.Channels, []int64{portal.ID, chB.ID}) {
		t.Fatalf("channels must stay without uids: %v", cb.Channels)
	}
}
