package cdn64

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

// listsAPI: ipv64 nimmt die Listen eines Tunnels an (OnlineAPI eingebettet: andere Aufrufe nicht noetig).
type listsAPI struct {
	OnlineAPI
	calls       int
	tunnel      string
	allow, deny []string
	err         error
}

func (a *listsAPI) SetLists(_ context.Context, tunnelID string, allow, deny []string) error {
	a.calls++
	if a.err != nil {
		return a.err
	}
	a.tunnel, a.allow, a.deny = tunnelID, allow, deny
	return nil
}

// Listen gehen nur bei Aenderung an ipv64 (je Tunnel), leer und nie geschickt gar nicht, nach einem Fehler erneut.
func TestOnlineListsSync(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	api := &listsAPI{}
	e.m.SetOnlineAPI(api)
	e.m.onlineListsSync(ctx, "t1")
	if api.calls != 0 {
		t.Fatal("empty lists never sent: nothing to do")
	}
	str := func(s string) *string { return &s }
	if err := e.m.blListsSave(ctx, str("192.0.2.1"), str("203.0.113.0/24\n198.51.100.7")); err != nil {
		t.Fatal(err)
	}
	e.m.onlineListsSync(ctx, "t1")
	if api.calls != 1 || api.tunnel != "t1" || len(api.deny) != 2 || len(api.allow) != 1 {
		t.Fatalf("sent: %+v", api)
	}
	e.m.onlineListsSync(ctx, "t1")
	if api.calls != 1 {
		t.Fatal("unchanged lists sent again")
	}
	e.m.onlineListsSync(ctx, "t2") // neuer Tunnel
	if api.calls != 2 || api.tunnel != "t2" {
		t.Fatal("new tunnel must get the lists")
	}
	api.err = errors.New("ipv64: HTTP 404")
	_ = e.m.blListsSave(ctx, nil, str(""))
	e.m.onlineListsSync(ctx, "t2")
	api.err = nil
	e.m.onlineListsSync(ctx, "t2")
	if api.calls != 4 || len(api.deny) != 0 || len(api.allow) != 1 {
		t.Fatalf("retry after error, emptied list: %+v", api)
	}
	// auf den Servern hoechstens onlineListMax Eintraege
	big := ""
	for i := 0; i < onlineListMax+5; i++ {
		big += "10." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250) + ".1\n"
	}
	_ = e.m.blListsSave(ctx, nil, &big)
	e.m.onlineListsSync(ctx, "t2")
	if len(api.deny) != onlineListMax {
		t.Fatalf("cut: %d", len(api.deny))
	}
}
