package environment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

func testBox(t *testing.T) *secrets.Box {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, err := secrets.New(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testPub(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return base64.StdEncoding.EncodeToString(pub)
}

// Zugangsschluessel: Form n64env1.<Kennung>.<Schluessel>.<Geheimnis>, alles andere wird abgelehnt.
func TestAccessKey(t *testing.T) {
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	k := AccessKey{NodeID: "AbC-def_0123456789xyz", PubKey: testPub(t), Secret: sec}
	got, err := ParseAccessKey("  " + k.String() + "\n")
	if err != nil || got.NodeID != k.NodeID || got.PubKey != k.PubKey || !bytes.Equal(got.Secret, sec) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	parts := strings.Split(k.String(), ".")
	for _, bad := range []string{"", "n64env1", "n64env2." + strings.Join(parts[1:], "."), strings.Join(parts[:3], "."),
		parts[0] + ".a.b." + parts[3], parts[0] + "." + parts[1] + "." + parts[2] + ".AAAA", k.String() + ".x", parts[0] + ".bad id!." + parts[2] + "." + parts[3]} {
		if _, err := ParseAccessKey(bad); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("accepted %q", bad)
		}
	}
	// der Pruefwert verraet das Geheimnis nicht und haengt nur von ihm ab
	if accessPub(sec) == accessPub(append([]byte{1}, sec[1:]...)) || strings.Contains(accessPub(sec), base64.RawURLEncoding.EncodeToString(sec)) {
		t.Fatal("check value")
	}
}

// Hinzugefuegte Nodes: Adresse normalisiert, mit Schluessel nur https, nie der eigene Schluessel; das Geheimnis liegt
// verschluesselt in der Datenbank.
func TestAddedNodes(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Now()
	fc := &fakeCluster{members: []peer.Member{{NodeID: "member-node-1", Name: "M"}}, areas: map[string]bool{}}
	d := fc.deps(st, &now)
	d.Box, d.NodeID = testBox(t), func() string { return "self-node-0001" }
	var changes []string
	d.Change = func(_ context.Context, module, item, id string, deleted bool) {
		changes = append(changes, module+"/"+item+"/"+id+"/"+strconv.FormatBool(deleted))
	}
	s := New(d)

	for in, want := range map[string]string{"node.lan:8443": "https://node.lan:8443", "http://10.0.0.5:8080/": "http://10.0.0.5:8080", "HTTPS://[fd00::1]:8443": "https://[fd00::1]:8443"} {
		if got, err := NormURL(in); err != nil || got != want {
			t.Errorf("NormURL(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ftp://x", "https://x/path", "https://user:pw@x", "https://x?a=1", "https://"} {
		if _, err := NormURL(bad); err == nil {
			t.Errorf("NormURL(%q) accepted", bad)
		}
	}

	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	key := AccessKey{NodeID: "target-node-01", PubKey: testPub(t), Secret: sec}
	if _, err := s.AddNode(ctx, NodeInput{URL: "http://b.lan:8080", Key: key.String()}, "0123456789abcdef"); !errors.Is(err, ErrHTTPSRequired) {
		t.Fatalf("http with key: %v", err)
	}
	for _, own := range []string{"self-node-0001", "member-node-1"} {
		k := key
		k.NodeID = own
		if _, err := s.AddNode(ctx, NodeInput{URL: "b.lan:8443", Key: k.String()}, "0123456789abcdef"); !errors.Is(err, ErrSelfKey) {
			t.Fatalf("own key %s: %v", own, err)
		}
	}
	if _, err := s.AddNode(ctx, NodeInput{URL: "b.lan:8443", Key: "n64env1.x"}, ""); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("invalid key: %v", err)
	}
	n, err := s.AddNode(ctx, NodeInput{URL: "b.lan:8443", Name: " Büro\nHamburg ", Description: "Keller", Key: key.String()}, "0123456789abcdef")
	if err != nil || !n.HasKey || n.URL != "https://b.lan:8443" || n.Name != "Büro Hamburg" || n.OwnerUID != "0123456789abcdef" || n.NodeID != "target-node-01" {
		t.Fatalf("add: %+v %v", n, err)
	}
	var raw string
	_ = st.Reader().QueryRow(`SELECT secret FROM env_nodes WHERE uid = ?`, n.UID).Scan(&raw)
	if !strings.HasPrefix(raw, "enc:v1:") || strings.Contains(raw, base64.RawURLEncoding.EncodeToString(sec)) {
		t.Fatalf("secret stored as %q", raw)
	}
	got, _ := s.AddedNode(ctx, n.UID)
	if k, err := s.key(got); err != nil || !bytes.Equal(k.Secret, sec) || k.PubKey != key.PubKey {
		t.Fatalf("key: %+v %v", k, err)
	}
	// Bearbeiten ohne Schluessel behaelt ihn; Entfernen nimmt ihn heraus
	n2, err := s.UpdateNode(ctx, n.UID, NodeInput{URL: "b.lan:9443", Name: "B"}, "fedcba9876543210")
	if err != nil || !n2.HasKey || n2.OwnerUID != "0123456789abcdef" || n2.URL != "https://b.lan:9443" {
		t.Fatalf("update keep: %+v %v", n2, err)
	}
	if _, err := s.UpdateNode(ctx, n.UID, NodeInput{URL: "http://b.lan:9080"}, ""); !errors.Is(err, ErrHTTPSRequired) {
		t.Fatalf("update to http with key: %v", err)
	}
	n3, err := s.UpdateNode(ctx, n.UID, NodeInput{URL: "http://b.lan:9080", RemoveKey: true}, "")
	if err != nil || n3.HasKey || n3.OwnerUID != "" {
		t.Fatalf("remove key: %+v %v", n3, err)
	}
	if x, _ := s.UpdateNode(ctx, "00000000000000000000000000000000", NodeInput{URL: "x.lan"}, ""); x != nil {
		t.Fatal("updated unknown node")
	}
	if ok, _ := s.RemoveNode(ctx, n.UID); !ok {
		t.Fatal("remove")
	}
	if len(changes) != 4 || !strings.HasSuffix(changes[3], "/true") || !strings.HasPrefix(changes[0], "environment/nodes/") {
		t.Fatalf("cluster changes: %v", changes)
	}
}

// Cluster: eine hinzugefuegte Node geht mit Schluessel auf das andere Mitglied, dort mit dessen Schluessel
// verschluesselt; Loeschen geht mit.
func TestAddedNodesCluster(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	fc := &fakeCluster{areas: map[string]bool{}}
	da, db := fc.deps(testStore(t), &now), fc.deps(testStore(t), &now)
	da.Box, db.Box = testBox(t), testBox(t)
	a, b := New(da), New(db)
	pa, pb := provider{a}, provider{b}
	if mi := pa.ClusterModule(); len(mi.Items) != 2 || mi.Items[1].ID != ItemNodes || !mi.Items[1].Default || !mi.Default {
		t.Fatalf("module: %+v", mi)
	}
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	key := AccessKey{NodeID: "target-node-01", PubKey: testPub(t), Secret: sec}
	n, err := a.AddNode(ctx, NodeInput{URL: "https://b.lan:8443", BrowserURL: "https://b.example.org", Description: "Büro", Key: key.String()}, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddNode(ctx, NodeInput{URL: "c.lan:8443"}, ""); err != nil {
		t.Fatal(err)
	}
	ids, _ := pa.ClusterIDs(ctx, ItemNodes)
	if len(ids) != 2 {
		t.Fatalf("ids: %v", ids)
	}
	for _, id := range ids {
		data, found, err := pa.ClusterGet(ctx, ItemNodes, id)
		if err != nil || !found {
			t.Fatal(found, err)
		}
		if err := pb.ClusterApply(ctx, ItemNodes, id, data, false); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := b.AddedNode(ctx, n.UID)
	if got == nil || !got.HasKey || got.OwnerUID != "0123456789abcdef" || got.BrowserURL != "https://b.example.org" || got.Description != "Büro" {
		t.Fatalf("applied: %+v", got)
	}
	k, err := b.key(got)
	if err != nil || !bytes.Equal(k.Secret, sec) {
		t.Fatalf("key on b: %v", err)
	}
	var sa, sb string
	_ = a.d.Store.Reader().QueryRow(`SELECT secret FROM env_nodes WHERE uid = ?`, n.UID).Scan(&sa)
	_ = b.d.Store.Reader().QueryRow(`SELECT secret FROM env_nodes WHERE uid = ?`, n.UID).Scan(&sb)
	if sa == sb || !strings.HasPrefix(sb, "enc:v1:") {
		t.Fatal("secret not re-encrypted on the receiver")
	}
	if _, err := a.key(&AddedNode{HasKey: true, sealed: sb, NodeID: "x", nodePub: "y"}); err == nil {
		t.Fatal("other node's ciphertext readable")
	}
	// ungueltige Daten werden abgelehnt
	for _, bad := range []string{`{"url":"ftp://x"}`, `{"url":"http://b.lan","secret":"` + base64.RawURLEncoding.EncodeToString(sec) + `","node_id":"target-node-01","node_pub":"` + key.PubKey + `"}`,
		`{"url":"https://b.lan","secret":"abc","node_id":"target-node-01","node_pub":"` + key.PubKey + `"}`} {
		if err := pb.ClusterApply(ctx, ItemNodes, "11111111111111111111111111111111", json.RawMessage(bad), false); err == nil {
			t.Errorf("applied %s", bad)
		}
	}
	if err := pb.ClusterApply(ctx, ItemNodes, n.UID, nil, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.AddedNode(ctx, n.UID); got != nil {
		t.Fatal("not deleted")
	}
	// environment/login gleicht nichts ab
	if ids, _ := pa.ClusterIDs(ctx, ItemLogin); len(ids) != 0 {
		t.Fatal("login ids")
	}
}

// signedReq baut eine gebundene Anfrage, wie die oeffnende Node sie schickt.
func signedReq(sec []byte, target, path string, bind, body []byte, at time.Time, nonce string) http.Header {
	ts := strconv.FormatInt(at.Unix(), 10)
	h := http.Header{}
	h.Set(hdrKey, accessPub(sec))
	h.Set(hdrTime, ts)
	h.Set(hdrSig, base64.StdEncoding.EncodeToString(ed25519.Sign(accessPair(sec), envMsg(path, ts, nonce, target, bind, body))))
	return h
}

// Zugaenge: Ticket nur mit gueltiger Signatur ueber genau diese Verbindung, frischer Nonce und Zeit, bekanntem Zugang
// und nicht gesperrtem Benutzer; Rolle begrenzt; Widerrufen wirkt sofort.
func TestRemoteAccess(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	fc := &fakeCluster{areas: map[string]bool{}}
	d := fc.deps(st, &now)
	pub := testPub(t)
	d.NodeID, d.PublicKey, d.NodeName, d.Version = func() string { return "node-b-000001" }, func() string { return pub }, func() string { return "Node B" }, "1.7.0"
	s := New(d)
	u, _ := st.CreateUserWith(ctx, store.NewUser{Username: "dennis", PasswordHash: "x", Lang: "de", Timezone: "UTC"})

	if _, _, err := s.CreateAccess(ctx, "von A", "ffffffffffffffff", "admin"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown user: %v", err)
	}
	a, keyStr, err := s.CreateAccess(ctx, "  von   Node A ", u.UID, "admin")
	if err != nil || a.Name != "von Node A" || a.Username != "dennis" {
		t.Fatalf("create: %+v %v", a, err)
	}
	key, err := ParseAccessKey(keyStr)
	if err != nil || key.NodeID != "node-b-000001" || key.PubKey != pub {
		t.Fatalf("key: %+v %v", key, err)
	}
	var stored string
	_ = st.Reader().QueryRow(`SELECT key_pub FROM env_access WHERE id = ?`, a.ID).Scan(&stored)
	if strings.Contains(keyStr, stored) || stored != accessPub(key.Secret) {
		t.Fatal("only the check value may be stored")
	}

	bind := bytes.Repeat([]byte{7}, 32)
	body, _ := json.Marshal(remoteTicketReq{Role: store.RoleAdmin, Back: "https://a.lan:8443/environment", FromNode: "node-a-000001", FromName: "Node A"})
	call := func(path string, h http.Header, nonce string, b []byte, bd []byte) RemoteResult {
		return s.HandleRemote(ctx, path, h, nonce, b, bd, "192.0.2.1", false)
	}
	n := 0
	nonce := func() string { n++; return "nonce-" + strconv.Itoa(1000000000+n) }

	// Status
	no := nonce()
	res := call(PathStatus, signedReq(key.Secret, key.NodeID, PathStatus, bind, nil, now, no), no, bind, nil)
	if st, ok := res.Body.(RemoteStatus); res.Status != 200 || !ok || st.Name != "Node B" || st.Version != "1.7.0" || st.User != "dennis" || st.NodeID != "node-b-000001" {
		t.Fatalf("status: %+v", res)
	}
	// Ticket
	no = nonce()
	res = call(PathTicket, signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now, no), no, bind, body)
	tr, ok := res.Body.(TicketResponse)
	if res.Status != 200 || !ok {
		t.Fatalf("ticket: %+v", res)
	}
	tk, ok := s.Redeem(tr.Ticket)
	if !ok || tk.UID != u.UID || tk.Role != store.RoleAdmin || tk.FromName != "Node A" || tk.FromNode != "node-a-000001" || tk.Back != "https://a.lan:8443/environment" {
		t.Fatalf("redeem: %+v", tk)
	}
	if a2, _ := s.AccessByID(ctx, a.ID); a2.LastFromName != "Node A" || a2.LastUsedAt.IsZero() {
		t.Fatalf("last use: %+v", a2)
	}
	// Wiederholung derselben Anfrage (gleiche Nonce)
	if res := call(PathTicket, signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now, no), no, bind, body); res.Status != 403 || !res.AuthFailed {
		t.Fatalf("replay: %+v", res)
	}
	// andere Verbindung (Mittelsmann): Signatur passt nicht zur eigenen Bindung
	no = nonce()
	other := bytes.Repeat([]byte{8}, 32)
	if res := call(PathTicket, signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now, no), no, other, body); res.Status != 403 || !res.AuthFailed {
		t.Fatalf("other binding: %+v", res)
	}
	// fuer eine andere Node signiert, anderer Pfad, veraenderter Body, alte Zeit, falsches Geheimnis
	wrong := make([]byte, 32)
	_, _ = rand.Read(wrong)
	for name, h := range map[string]func(string) http.Header{
		"target": func(no string) http.Header {
			return signedReq(key.Secret, "node-x-000001", PathTicket, bind, body, now, no)
		},
		"path": func(no string) http.Header { return signedReq(key.Secret, key.NodeID, PathStatus, bind, body, now, no) },
		"body": func(no string) http.Header {
			return signedReq(key.Secret, key.NodeID, PathTicket, bind, []byte(`{}`), now, no)
		},
		"time": func(no string) http.Header {
			return signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now.Add(-10*time.Minute), no)
		},
		"secret": func(no string) http.Header { return signedReq(wrong, key.NodeID, PathTicket, bind, body, now, no) },
	} {
		no := nonce()
		if res := call(PathTicket, h(no), no, bind, body); res.Status != 403 || !res.AuthFailed {
			t.Errorf("%s: %+v", name, res)
		}
	}
	// Rolle begrenzt: hier nur lesen
	_ = st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleRead})
	no = nonce()
	res = call(PathTicket, signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now, no), no, bind, body)
	if tk, _ := s.Redeem(res.Body.(TicketResponse).Ticket); tk == nil || tk.Role != store.RoleRead {
		t.Fatalf("role: %+v", tk)
	}
	// gesperrt: abgelehnt, aber kein Fehlversuch (der Schluessel war echt)
	_ = st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleAdmin, Disabled: true})
	no = nonce()
	if res := call(PathTicket, signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now, no), no, bind, body); res.Status != 403 || res.AuthFailed ||
		res.Body.(map[string]string)["error"] != ErrLocked.Error() {
		t.Fatalf("locked: %+v", res)
	}
	_ = st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleAdmin})
	// Widerruf: offenes Ticket verfaellt, ueber den Zugang geoeffnete Sitzung endet, andere Sitzungen bleiben
	no = nonce()
	res = call(PathTicket, signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now, no), no, bind, body)
	openTk := res.Body.(TicketResponse).Ticket
	no = nonce()
	res = call(PathTicket, signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now, no), no, bind, body)
	if tk, _ := s.Redeem(res.Body.(TicketResponse).Ticket); tk == nil || tk.AccessID != a.ID {
		t.Fatalf("ticket without access: %+v", tk)
	}
	for _, id := range []string{"via-access", "via-cluster"} {
		wall := time.Now()
		if err := st.CreateSession(ctx, &store.Session{ID: id, UserID: u.ID, CSRF: "c", CreatedAt: wall, LastSeenAt: wall, ExpiresAt: wall.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.SaveSession(ctx, "via-access", Origin{MaxRole: store.RoleAdmin, FromName: "A", AccessID: a.ID})
	_ = s.SaveSession(ctx, "via-cluster", Origin{MaxRole: store.RoleAdmin, FromNode: "node-c"})
	if o, _ := s.SessionOrigin(ctx, "via-access"); o == nil || o.AccessID != a.ID {
		t.Fatalf("session origin: %+v", o)
	}
	if ok, _ := s.RevokeAccess(ctx, a.ID); !ok {
		t.Fatal("revoke")
	}
	if _, ok := s.Redeem(openTk); ok {
		t.Fatal("open ticket of a revoked access still redeemable")
	}
	if x, _ := st.SessionByID(ctx, "via-access"); x != nil {
		t.Fatal("session of a revoked access still alive")
	}
	if x, _ := st.SessionByID(ctx, "via-cluster"); x == nil {
		t.Fatal("other session ended")
	}
	if ok, _ := s.RevokeAccess(ctx, a.ID); ok {
		t.Fatal("second revoke")
	}
	no = nonce()
	if res := call(PathTicket, signedReq(key.Secret, key.NodeID, PathTicket, bind, body, now, no), no, bind, body); res.Status != 403 || !res.AuthFailed {
		t.Fatalf("revoked: %+v", res)
	}
	if list, _ := s.Accesses(ctx); len(list) != 0 {
		t.Fatal("access list after revoke")
	}
	// Audit-Log: abgelehnte Anfragen als environment.ticket_denied
	entries, _ := st.AuditList(ctx, 50, 0)
	denied := 0
	for _, e := range entries {
		if e.Action == "environment.ticket_denied" && e.IP == "192.0.2.1" {
			denied++
		}
	}
	if denied < 8 {
		t.Fatalf("denied in audit: %d", denied)
	}
	// Oeffnen: nur der Benutzer, der den Schluessel eingetragen hat
	if _, err := s.RequestRemoteTicket(ctx, &AddedNode{HasKey: true, OwnerUID: "0123456789abcdef"}, "fedcba9876543210", store.RoleAdmin, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("other user: %v", err)
	}
}
