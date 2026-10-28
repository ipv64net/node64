package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func pair(t *testing.T, host, joiner *testNode) {
	t.Helper()
	code, _, err := host.m.StartPairing()
	if err != nil {
		t.Fatal(err)
	}
	if err := joiner.m.Join(context.Background(), host.srv.URL, code, joiner.srv.URL); err != nil {
		t.Fatal(err)
	}
}

func memberOf(t *testing.T, n *testNode, id string) Member {
	t.Helper()
	x, err := n.m.member(context.Background(), id)
	if err != nil || x == nil {
		t.Fatalf("%s: member %s missing (%v)", n.m.d.NodeName(), id, err)
	}
	return *x
}

func wantState(t *testing.T, n *testNode, id, reason string) {
	t.Helper()
	x := memberOf(t, n, id)
	if reason == "" && x.Suspended() || reason != "" && (!x.Suspended() || x.Reason != reason) {
		t.Fatalf("%s -> %s: state=%q reason=%q, want reason %q", n.m.d.NodeName(), x.Name, x.State, x.Reason, reason)
	}
}

func wantPingOK(t *testing.T, n *testNode) {
	t.Helper()
	ctx := context.Background()
	n.m.pingAll(ctx)
	for _, x := range n.m.activeMembers(ctx) {
		if !x.Online() || x.LastError != "" {
			t.Fatalf("%s -> %s: online=%v err=%q", n.m.d.NodeName(), x.Name, x.Online(), x.LastError)
		}
	}
}

// mitm ist ein TLS-terminierender Proxy vor einer Node (selbst signiert, wie ein Reverse-Proxy dazwischen).
func mitm(t *testing.T, to *testNode) *httptest.Server {
	t.Helper()
	u, _ := url.Parse(to.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // Test
	s := httptest.NewTLSServer(rp)
	t.Cleanup(s.Close)
	return s
}

// wantActive: alle Mitglieder aktiv, Pings ohne Fehler.
func wantActive(t *testing.T, n *testNode, count int) {
	t.Helper()
	wantPingOK(t, n)
	if got := len(n.m.activeMembers(context.Background())); got != count {
		t.Fatalf("%s: %d active members, want %d", n.m.d.NodeName(), got, count)
	}
}

// Accounts im Cluster: gleich oder eine Node ohne (0), nie zwei verschiedene.
func TestClusterWithoutAccount(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 0), newNode(t, "node-b", "B", 0)
	x, y := newNode(t, "node-x", "X", 522), newNode(t, "node-y", "Y", 999)
	pair(t, a, b) // beide ohne ipv64
	waitMembers(t, a, "B")
	wantPingOK(t, a)
	wantPingOK(t, b)
	// eine Node mit Account darf zu Nodes ohne
	pair(t, a, x)
	waitMembers(t, a, "B", "X")
	waitMembers(t, b, "A", "X")
	waitMembers(t, x, "A", "B")
	for _, n := range []*testNode{a, b, x} {
		wantActive(t, n, 2)
	}
	if acc := b.m.ClusterAccount(ctx); acc != 522 {
		t.Fatalf("cluster account seen by B: %d", acc)
	}
	// ein zweiter Account nie, auch nicht ueber eine Node ohne Account (in beide Richtungen)
	code, _, _ := a.m.StartPairing()
	if err := y.m.Join(ctx, a.srv.URL, code, y.srv.URL); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("Y (999) joins A (0, cluster 522): %v", err)
	}
	code, _, _ = y.m.StartPairing()
	if err := b.m.Join(ctx, y.srv.URL, code, b.srv.URL); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("B (0, cluster 522) joins Y (999): %v", err)
	}
	// eine Node ohne Account bekommt einen anderen: ausgesetzt, die anderen arbeiten weiter
	b.acc = 999
	b.m.pingAll(ctx)
	wantState(t, b, "node-x", ReasonAccountChanged)
	a.m.pingAll(ctx)
	x.m.pingAll(ctx)
	wantState(t, a, "node-b", ReasonAccountMismatch)
	wantState(t, x, "node-b", ReasonAccountMismatch)
	wantState(t, a, "node-x", "")
}

func TestClusterHTTPSOnly(t *testing.T) {
	ctx := context.Background()
	a := newNode(t, "node-a", "A", 522)
	mux := http.NewServeMux()
	a.m.Register(mux)
	plain := httptest.NewServer(mux)
	defer plain.Close()
	for _, p := range []string{"/peer/v1/ping", "/peer/v1/pair"} {
		method := http.MethodGet
		if strings.HasSuffix(p, "pair") {
			method = http.MethodPost
		}
		req, _ := http.NewRequest(method, plain.URL+p, strings.NewReader("{}"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUpgradeRequired {
			t.Fatalf("plain http %s: %d", p, resp.StatusCode)
		}
	}
	// Node ohne HTTPS-Port
	b := newNode(t, "node-b", "B", 522)
	b.m.d.HTTPSPort = func() int { return 0 }
	if _, _, err := b.m.StartPairing(); !errors.Is(err, ErrNoHTTPS) {
		t.Fatalf("pairing without https: %v", err)
	}
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); !errors.Is(err, ErrNoHTTPS) {
		t.Fatalf("join without https: %v", err)
	}
	// Adressen werden https
	if got := httpsURL("http://10.0.0.5:8080/"); got != "https://10.0.0.5:8080" {
		t.Fatal(got)
	}
	if got := httpsURL("10.0.0.5:8443"); got != "https://10.0.0.5:8443" {
		t.Fatal(got)
	}
	if got := selfAddr("http://[fd00::5]:8080", 8443); got != "https://[fd00::5]:8080" {
		t.Fatal(got)
	}
	if got := selfAddr("https://node.example.com", 8443); got != "https://node.example.com:8443" {
		t.Fatal(got)
	}
}

func TestClusterTLSBinding(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-c", "C", 522)
	pair(t, a, b)
	waitMembers(t, a, "B")
	// Kopplung ueber einen Mittelsmann: abgelehnt, der Code bleibt gueltig
	code, _, _ := a.m.StartPairing()
	if err := c.m.Join(ctx, mitm(t, a).URL, code, c.srv.URL); !errors.Is(err, ErrTLSBinding) {
		t.Fatalf("join through proxy: %v", err)
	}
	if c2, _ := a.m.PairingCode(); c2 != code {
		t.Fatal("a relayed attempt must not use up the code")
	}
	// A erreicht B nur noch ueber den Mittelsmann: B lehnt ab, A setzt B aus
	if err := a.m.SetURL(ctx, "node-b", mitm(t, b).URL); err != nil {
		t.Fatal(err)
	}
	a.m.pingAll(ctx)
	wantState(t, a, "node-b", ReasonTLSBinding)
	if err := a.m.call(ctx, memberOf(t, a, "node-b"), http.MethodGet, "/peer/v1/ping", nil, nil); !errors.Is(err, ErrSuspended) {
		t.Fatalf("call to suspended member: %v", err)
	}
	// B fragt A direkt: A nimmt von B nichts mehr an (ausser Ping)
	if err := b.m.call(ctx, memberOf(t, b, "node-a"), http.MethodPost, "/peer/v1/poke", map[string]string{}, nil); !errors.Is(err, errSuspendedThere) {
		t.Fatalf("request of a suspended member: %v", err)
	}
	// Wiederaufnehmen ueber den Mittelsmann scheitert, direkt klappt es
	if err := a.m.Resume(ctx, "node-b"); !errors.Is(err, ErrSuspended) {
		t.Fatalf("resume through proxy: %v", err)
	}
	wantState(t, a, "node-b", ReasonTLSBinding)
	_ = a.m.SetURL(ctx, "node-b", b.srv.URL)
	if err := a.m.Resume(ctx, "node-b"); err != nil {
		t.Fatal(err)
	}
	wantState(t, a, "node-b", "")
	wantPingOK(t, a)
	wantPingOK(t, b)
}

func TestClusterIdentityAndVersion(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-c", "C", 522)
	pair(t, a, b)
	pair(t, a, c)
	waitMembers(t, a, "B", "C")
	// an der Adresse von B antwortet C
	_ = a.m.SetURL(ctx, "node-b", c.srv.URL)
	a.m.pingAll(ctx)
	wantState(t, a, "node-b", ReasonIdentityChanged)
	wantState(t, a, "node-c", "") // die anderen arbeiten weiter
	// eine aeltere Version (alte Signatur, keine Cluster-Antwort) an der Adresse von C
	old := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
	}))
	defer old.Close()
	_ = a.m.SetURL(ctx, "node-c", old.URL)
	a.m.pingAll(ctx)
	wantState(t, a, "node-c", ReasonVersionTooOld)
}

func TestClusterSuspendResume(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-c", "C", 522)
	pair(t, a, b)
	pair(t, b, c)
	waitMembers(t, a, "B", "C")
	waitMembers(t, c, "A", "B")
	// Account von C wechselt: C setzt alle aus, A und B setzen C aus, A und B arbeiten weiter
	c.acc = 999
	c.m.pingAll(ctx)
	wantState(t, c, "node-a", ReasonAccountChanged)
	wantState(t, c, "node-b", ReasonAccountChanged)
	a.m.pingAll(ctx)
	b.m.pingAll(ctx)
	wantState(t, a, "node-c", ReasonAccountMismatch)
	wantState(t, b, "node-c", ReasonAccountMismatch)
	wantState(t, a, "node-b", "")
	wantPingOK(t, a)
	wantPingOK(t, b)
	// solange der Account nicht passt, bleibt C ausgesetzt
	if err := a.m.Resume(ctx, "node-c"); !errors.Is(err, ErrSuspended) || !strings.Contains(err.Error(), ReasonAccountMismatch) {
		t.Fatalf("resume with other account: %v", err)
	}
	// C zurueck auf 522: jede Seite nimmt bei sich wieder auf
	c.acc = 522
	for _, r := range []struct {
		n  *testNode
		id string
	}{{a, "node-c"}, {b, "node-c"}, {c, "node-a"}, {c, "node-b"}} {
		if err := r.n.m.Resume(ctx, r.id); err != nil {
			t.Fatalf("%s resumes %s: %v", r.n.m.d.NodeName(), r.id, err)
		}
	}
	for _, n := range []*testNode{a, b, c} {
		wantPingOK(t, n)
		if len(n.m.activeMembers(ctx)) != 2 {
			t.Fatalf("%s: not all members active", n.m.d.NodeName())
		}
	}
	if err := a.m.Resume(ctx, "node-x"); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("resume unknown: %v", err)
	}
}

func TestClusterAccountMovesTogether(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 0), newNode(t, "node-b", "B", 0)
	pair(t, a, b)
	waitMembers(t, a, "B")
	// A verknuepft sich mit ipv64 (0 -> 777): passt (B ohne), nichts ausgesetzt; dann B ebenso
	a.acc = 777
	wantActive(t, a, 1)
	wantActive(t, b, 1)
	if x := memberOf(t, b, "node-a"); x.AccountID != 777 || x.SelfAccount != 0 {
		t.Fatalf("B sees A: %+v", x)
	}
	b.acc = 777
	wantActive(t, b, 1)
	wantActive(t, a, 1)
	if x := memberOf(t, a, "node-b"); x.AccountID != 777 || x.SelfAccount != 777 || x.Suspended() {
		t.Fatalf("A sees B: %+v", x)
	}
	// A verliert den Account (Key entfernt, 777 -> 0): passt weiter
	a.acc = 0
	wantActive(t, a, 1)
	wantActive(t, b, 1)
	if x := memberOf(t, b, "node-a"); x.AccountID != 0 {
		t.Fatalf("B sees A without account: %+v", x)
	}
	// A bekommt danach einen anderen als der Cluster (0 -> 888, B hat 777): A setzt aus, B ebenso
	a.acc = 888
	a.m.pingAll(ctx)
	wantState(t, a, "node-b", ReasonAccountChanged)
	b.m.pingAll(ctx)
	wantState(t, b, "node-a", ReasonAccountMismatch)
}

func TestNonceReplay(t *testing.T) {
	a := newNode(t, "node-a", "A", 522)
	if !a.m.nonceFresh("0123456789abcdef") || a.m.nonceFresh("0123456789abcdef") {
		t.Fatal("a nonce must be accepted once")
	}
}
