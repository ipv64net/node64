package notify

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
)

type nfChange struct {
	uid     string
	deleted bool
}

type nfLog struct {
	mu    sync.Mutex
	calls []nfChange
}

func (l *nfLog) hook(_ context.Context, uid string, deleted bool) {
	l.mu.Lock()
	l.calls = append(l.calls, nfChange{uid, deleted})
	l.mu.Unlock()
}

func (l *nfLog) take() []nfChange {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.calls
	l.calls = nil
	return out
}

// nfTransfer uebertraegt die gemeldeten Kanaele von a nach b (wie der Cluster: Stand holen, uebernehmen).
func nfTransfer(t *testing.T, a, b *Store, calls []nfChange) {
	t.Helper()
	ctx := context.Background()
	for _, c := range calls {
		data, found, err := a.ClusterGet(ctx, ClusterItemChannels, c.uid)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ClusterApply(ctx, ClusterItemChannels, c.uid, data, c.deleted || !found); err != nil {
			t.Fatalf("apply %+v: %v", c, err)
		}
	}
}

func rawConfig(t *testing.T, s *Store, uid string) string {
	t.Helper()
	var raw string
	_ = s.r.QueryRow(`SELECT config FROM nf_channels WHERE uid = ?`, uid).Scan(&raw)
	return raw
}

// Kanaele ueber den Cluster: nur eigene Kanaele der Node, Geheimnisse mit dem Schluessel der empfangenden Node,
// Server-ID und Zustand bleiben je Node; Aendern und Loeschen kommen an.
func TestChannelClusterSync(t *testing.T) {
	ctx := context.Background()
	a, b := testStore(t), testStore(t)
	var la, lb nfLog
	a.SetCluster(la.hook)
	b.SetCluster(lb.hook)

	tg := &Channel{Type: TypeTelegram, Name: "tg", Config: map[string]string{"bot_token": "123:GEHEIM", "chat_id": "42"}, Enabled: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "node"}
	for _, c := range []*Channel{
		tg,
		{Type: TypeDiscord, Name: "nur lokal", Config: map[string]string{"webhook_url": "https://discord.example/x"}, Enabled: true, SecretOnlyLocal: true, Execution: "node"},
		{Type: TypeIPv64Mail, Name: "Portal", Config: map[string]string{}, Enabled: true, Execution: "server", RemoteID: 9},
		{Type: TypeWebhook, Name: "Portal-Webhook", Config: map[string]string{}, Enabled: true, Execution: "server", RemoteID: 10},
		{Type: TypeBrowser, Name: "Browser", Config: map[string]string{}, Enabled: true, Execution: "node"},
	} {
		if err := a.Insert(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	calls := la.take()
	if len(calls) != 1 || calls[0] != (nfChange{tg.UID, false}) {
		t.Fatalf("only the own channel goes to the cluster: %+v", calls)
	}
	if ids, _ := a.ClusterIDs(ctx, ClusterItemChannels); !slices.Equal(ids, []string{tg.UID}) {
		t.Fatalf("ids: %v", ids)
	}
	_ = b.Insert(ctx, &Channel{Type: TypeNtfy, Name: "vorher", Config: map[string]string{"server": "https://ntfy.sh", "topic": "x"}, Enabled: true, Execution: "node"})
	lb.take()
	nfTransfer(t, a, b, calls)

	got, _ := b.byUID(ctx, tg.UID)
	if got == nil || got.ID == tg.ID || got.Config["bot_token"] != "123:GEHEIM" || got.Name != "tg" || got.RemoteID != 0 || got.Execution != "node" {
		t.Fatalf("channel on B: %+v", got)
	}
	rawA, rawB := rawConfig(t, a, tg.UID), rawConfig(t, b, tg.UID)
	if strings.Contains(rawB, "GEHEIM") || !strings.Contains(rawB, "enc:v1:") || rawA == rawB {
		t.Fatalf("secret must be re-encrypted with B's key: %s", rawB)
	}
	if c := lb.take(); len(c) != 1 || c[0].uid != tg.UID {
		t.Fatalf("B reports the applied channel: %+v", c)
	}
	if b.ClusterIDOf(ctx, tg.UID) != got.ID || b.ClusterUIDOf(ctx, got.ID) != tg.UID {
		t.Fatal("uid mapping on B")
	}

	// Aenderung auf B kommt bei A an (Server-ID auf A bleibt), Loeschen auf A kommt bei B an
	_ = a.SetRemote(ctx, tg.ID, 77, 3)
	got.Name, got.Config["chat_id"] = "tg neu", "43"
	if err := b.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	nfTransfer(t, b, a, lb.take())
	if c, _ := a.Channel(ctx, tg.ID); c.Name != "tg neu" || c.Config["chat_id"] != "43" || c.Config["bot_token"] != "123:GEHEIM" || c.RemoteID != 77 {
		t.Fatalf("update on A: %+v", c)
	}
	// „Geheimnis nur lokal“ eingeschaltet: geht als geloescht hinaus
	la.take()
	c, _ := a.Channel(ctx, tg.ID)
	c.SecretOnlyLocal = true
	_ = a.Update(ctx, c)
	if calls := la.take(); len(calls) != 1 || !calls[0].deleted {
		t.Fatalf("no longer shared: %+v", calls)
	}
	nfTransfer(t, a, b, []nfChange{{tg.UID, true}})
	if x, _ := b.byUID(ctx, tg.UID); x != nil {
		t.Fatal("delete must reach B")
	}
	// hier nicht (mehr) geteilt: eine Loeschung aus dem Cluster laesst ihn stehen
	if err := a.ClusterApply(ctx, ClusterItemChannels, tg.UID, nil, true); err != nil {
		t.Fatal(err)
	}
	if x, _ := a.Channel(ctx, tg.ID); x == nil {
		t.Fatal("local-only channel must stay")
	}
}

// Exaktes Doppel (auf beiden Nodes gleich angelegt, samt Geheimnis): beide landen bei der kleineren Kennung, lokale
// Nummer bleibt; ein Kanal mit anderem Geheimnis ist kein Doppel.
func TestChannelClusterDuplicate(t *testing.T) {
	ctx := context.Background()
	a, b := testStore(t), testStore(t)
	var la, lb nfLog
	a.SetCluster(la.hook)
	b.SetCluster(lb.hook)
	uidA, uidB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	ch := func(uid, secret string) *Channel {
		return &Channel{Type: TypeDiscord, Name: "Discord", Config: map[string]string{"webhook_url": secret}, Enabled: true, NotifyDown: true, Lang: "de", Execution: "node", UID: uid}
	}
	_ = b.Insert(ctx, ch(strings.Repeat("e", 32), "https://discord.example/anders")) // aehnlich, anderes Geheimnis
	ca := ch(uidA, "https://discord.example/geheim")
	cb := ch(uidB, "https://discord.example/geheim")
	_ = a.Insert(ctx, ca)
	_ = b.Insert(ctx, cb)
	callsA, callsB := la.take(), lb.take()
	nfTransfer(t, a, b, callsA) // B uebernimmt die kleinere Kennung
	nfTransfer(t, b, a, callsB) // A behaelt seine
	callsB = lb.take()
	if !slices.Contains(callsB, nfChange{uidB, true}) {
		t.Fatalf("B must report its old uid as deleted: %+v", callsB)
	}
	nfTransfer(t, b, a, callsB)
	nfTransfer(t, a, b, la.take())
	for _, s := range []*Store{a, b} {
		ids, _ := s.ClusterIDs(ctx, ClusterItemChannels)
		slices.Sort(ids)
		if !slices.Equal(ids, []string{uidA, strings.Repeat("e", 32)}) {
			t.Fatalf("channels: %v", ids)
		}
	}
	if b.ClusterIDOf(ctx, uidA) != cb.ID {
		t.Fatal("local number on B must stay")
	}
}
