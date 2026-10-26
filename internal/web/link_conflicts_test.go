package web

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/healthchecks"
	nodesync "github.com/ipv64net/node64/internal/sync"
)

// fakeLinker merkt sich die Entscheidungen zu Konflikten.
type fakeLinker struct {
	nodesync.Linker
	resolved []string
}

func (f *fakeLinker) Resolve(_ context.Context, id int64, keep string) error {
	f.resolved = append(f.resolved, keep)
	return nil
}

// Konflikte sind Ablehnungen des hub: Grund und beide Fassungen sichtbar; "ipv64-Stand übernehmen" nur mit
// Server-Fassung, "Hier löschen" nur, wenn ipv64 den Eintrag nicht hat; alte Konflikte ohne Grund loeschen nie.
func TestLinkConflictsRejected(t *testing.T) {
	ctx := context.Background()
	fl := &fakeLinker{}
	var hc *healthchecks.Module
	a := newTestAppDeps(t, func(d *Deps) {
		hc = healthchecks.New(d.Store, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, "test")
		if err := d.Store.Migrate(ctx, "healthchecks", hc.Migrations()); err != nil {
			t.Fatal(err)
		}
		d.HC, d.Linker = hc, fl
	})
	loginAs(t, a, "admin", "sehr geheimes passwort")
	for _, c := range []healthchecks.Conflict{
		{Entity: "check", EntityID: "tokA", LocalOp: "upsert", LocalPayload: `{"name":"Mit Server","type":"docker"}`, ServerPayload: `{"name":"Server-Name","revision":7}`, ServerRevision: 7,
			Error: "docker checks belong to the node that runs them and cannot be moved"},
		{Entity: "check", EntityID: "tokB", LocalOp: "upsert", LocalPayload: `{"name":"Neu","type":"http"}`, Error: "online limit reached (10 of 10 measuring points)"},
		{Entity: "check", EntityID: "tokC", LocalOp: "upsert", LocalPayload: `{"name":"Alt","type":"http"}`},
	} {
		if err := hc.ConflictAdd(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	resp, body := a.get(t, "/link")
	if resp.StatusCode != 200 {
		t.Fatalf("link: %d", resp.StatusCode)
	}
	for _, want := range []string{"cannot be moved", "online limit reached", "Server-Name", "bei ipv64 nicht vorhanden", `value="ignore"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("%q missing", want)
		}
	}
	if strings.Contains(body, "{{count}}") || strings.Contains(body, "{3}") {
		t.Fatal("count placeholder")
	}
	cards := strings.Split(body, `action="/link/conflicts/`)[1:]
	if len(cards) != 3 {
		t.Fatalf("cards: %d", len(cards))
	}
	// A: Server-Fassung -> uebernehmen, kein Loeschen; B: nicht vorhanden -> Loeschen; C: alt -> weder noch
	if !strings.Contains(cards[0], "ipv64-Stand übernehmen") || strings.Contains(cards[0], "Hier löschen") ||
		!strings.Contains(cards[1], "Hier löschen") || strings.Contains(cards[1], "ipv64-Stand übernehmen") ||
		strings.Contains(cards[2], `value="server"`) || !strings.Contains(cards[2], `value="local"`) {
		t.Fatal("buttons per conflict")
	}
	csrf := csrfOf(t, body)
	list, _ := hc.Conflicts(ctx)
	for _, keep := range []string{"ignore", "local", "server", "bogus"} {
		if resp, _ := a.post(t, "/link/conflicts/"+strconv.FormatInt(list[0].ID, 10), url.Values{"_csrf": {csrf}, "keep": {keep}}); resp.StatusCode != 303 {
			t.Fatalf("resolve %s: %d", keep, resp.StatusCode)
		}
	}
	if strings.Join(fl.resolved, ",") != "ignore,local,server,server" {
		t.Fatalf("resolved: %v", fl.resolved)
	}
}
