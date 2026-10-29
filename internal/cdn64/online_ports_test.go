package cdn64

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/tunnel"
)

// visitorConn: Ende eines Tunnel-Streams mit der Besucher-Adresse aus dem Kopf.
type visitorConn struct {
	net.Conn
	ra net.Addr
}

func (c *visitorConn) RemoteAddr() net.Addr { return c.ra }

// Portmapper Modus 1/2: Stream ueber einen CDN64-Namen anmelden, Verbindungen aus dem Tunnel (TCP, UDP) an den
// Stream, Abmelden, Neuanmelden nach Verlust bei ipv64.
func TestOnlinePorts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if res, err := e.m.onlineEnable(ctx, h, 1); err != nil || len(res) != 1 || res[0].Result != "on" {
		t.Fatalf("enable: %v %+v", err, res)
	}
	// Ziele im Heimnetz: TCP-Echo, UDP-Echo
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 64)
				n, _ := c.Read(b)
				_, _ = c.Write(append([]byte("T:"), b[:n]...))
			}()
		}
	}()
	ul, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	go func() {
		b := make([]byte, 64)
		for {
			n, from, err := ul.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = ul.WriteTo(append([]byte("U:"), b[:n]...), from)
		}
	}()
	_, tport, _ := net.SplitHostPort(tl.Addr().String())
	_, uport, _ := net.SplitHostPort(ul.LocalAddr().String())
	// ein Port fuer TCP und UDP: das Ziel ist je Protokoll ein anderes Echo -> zwei Streams
	sp := freePort(t)
	st := &Stream{Name: "Spiel", Enabled: true, ListenPort: sp, TCP: true, TargetHost: "127.0.0.1", OnlineName: "app.test"}
	st.TargetPort, _ = strconv.Atoi(tport)
	if err := e.m.saveStream(ctx, st); err != nil {
		t.Fatal(err)
	}
	su := &Stream{Name: "WireGuard", Enabled: true, ListenPort: sp, UDP: true, TargetHost: "127.0.0.1", OnlineName: "app.test"}
	su.TargetPort, _ = strconv.Atoi(uport)
	if err := e.m.saveStream(ctx, su); err != nil {
		t.Fatal(err)
	}
	rows, _ := e.m.onlinePortRows(ctx)
	list, _ := e.m.onlineNames(ctx)
	rid := list[0].RemoteID
	if len(rows) != 2 || len(f.maps[rid]) != 2 || rows[0].TargetPort != sp || f.maps[rid][0].Name != "Spiel" {
		t.Fatalf("mappings: rows %+v remote %+v", rows, f.maps[rid])
	}
	visitor := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000}
	open := func(kind, host string, port int) net.Conn {
		a, b := net.Pipe()
		go e.m.onlinePortStream(&visitorConn{Conn: b, ra: visitor}, tunnel.Header{Kind: kind, Host: host, Port: port, Client: visitor.String()})
		_ = a.SetDeadline(time.Now().Add(5 * time.Second))
		return a
	}
	c := open(tunnel.KindTCP, "APP.test", sp)
	_, _ = c.Write([]byte("hi"))
	got, _ := io.ReadAll(c)
	c.Close()
	if string(got) != "T:hi" {
		t.Fatalf("tcp via tunnel: %q", got)
	}
	u := open(tunnel.KindUDP, "app.test", sp)
	if err := tunnel.WriteDatagram(u, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, tunnel.MaxDatagram)
	n, err := tunnel.ReadDatagram(u, buf)
	u.Close()
	if err != nil || string(buf[:n]) != "U:ping" {
		t.Fatalf("udp via tunnel: %q %v", buf[:n], err)
	}
	if s := e.m.streamStatsOf(st.ID); s.conns.Load() != 1 || s.bytesIn.Load() != 2 {
		t.Fatalf("stream stats: conns %d in %d", s.conns.Load(), s.bytesIn.Load())
	}
	// Grenze je Stream: volle UDP-Sitzungen -> neue werden geschlossen
	e.m.smu.Lock()
	run := e.m.runs[su.ID]
	e.m.smu.Unlock()
	for i := 0; i < 300 && run.tunUDP.Load() != 0; i++ { // die vorige Sitzung endet asynchron (zaehlt sonst danach herunter)
		time.Sleep(10 * time.Millisecond)
	}
	run.tunUDP.Store(udpMaxSessions)
	u = open(tunnel.KindUDP, "app.test", sp)
	_ = tunnel.WriteDatagram(u, []byte("x"))
	if _, err := tunnel.ReadDatagram(u, buf); err == nil {
		t.Fatal("udp session over the limit must be closed")
	}
	u.Close()
	run.tunUDP.Store(0)
	for _, x := range []struct {
		kind, host string
		port       int
	}{{tunnel.KindTCP, "other.test", sp}, {tunnel.KindTCP, "app.test", sp + 1}} {
		c := open(x.kind, x.host, x.port)
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && err == nil {
			t.Fatalf("%+v must be closed", x)
		}
		c.Close()
	}
	// Liste zeigt den Port der Server
	srows, _ := e.m.streamRows(ctx)
	if len(srows[0].Online) != 1 || srows[0].Online[0].ListenPort < 50000 || srows[0].Online[0].Name != "app.test" {
		t.Fatalf("stream row: %+v", srows[0].Online)
	}
	page := renderPage(t, "streams.html", streamsData{Streams: srows, Local: srows})
	if !strings.Contains(page, "app.test:"+strconv.Itoa(srows[0].Online[0].ListenPort)) {
		t.Fatal("streams page misses the server port")
	}
	fd := e.m.streamFormData(ctx, st, false)
	fd.OnlineOn = true
	if form := renderPage(t, "stream_form.html", fd); !strings.Contains(form, `<option value="app.test" selected>`) {
		t.Fatal("stream form misses the CDN64 name")
	}
	// bei ipv64 verloren (z. B. auf der Webseite entfernt): der Abgleich meldet neu an
	f.mu.Lock()
	f.maps[rid] = f.maps[rid][1:]
	f.mu.Unlock()
	e.m.onlineSync(ctx)
	if rows, _ := e.m.onlinePortRows(ctx); len(rows) != 2 || len(f.maps[rid]) != 2 {
		t.Fatalf("after loss: rows %d remote %d", len(rows), len(f.maps[rid]))
	}
	// Fehler beim Anmelden (Kontingent) steht am Stream
	su.OnlineName = ""
	if err := e.m.saveStream(ctx, su); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.mapErr = &ipv64api.APIError{Status: 403, Code: "limit_reached"}
	f.mu.Unlock()
	su.OnlineName = "app.test"
	if err := e.m.saveStream(ctx, su); err != nil {
		t.Fatal(err)
	}
	if _, errs := e.m.onlinePortsOf(ctx); errs[su.ID] != "limit_reached" {
		t.Fatalf("error: %v", errs)
	}
	// nur noch hier: abmelden
	st.OnlineName, su.OnlineName = "", ""
	_ = e.m.saveStream(ctx, st)
	_ = e.m.saveStream(ctx, su)
	if rows, _ := e.m.onlinePortRows(ctx); len(rows) != 0 || len(f.maps[rid]) != 0 {
		t.Fatalf("after off: rows %d remote %+v", len(rows), f.maps[rid])
	}
	c = open(tunnel.KindTCP, "app.test", sp)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream without CDN64 must not be reachable through the tunnel")
	}
	c.Close()
	// Stream geloescht bzw. Name ausgeschaltet: Mappings weg
	st.OnlineName = "app.test"
	_ = e.m.saveStream(ctx, st)
	if err := e.m.deleteStream(ctx, st.ID); err != nil {
		t.Fatal(err)
	}
	if rows, _ := e.m.onlinePortRows(ctx); len(rows) != 0 || len(f.maps[rid]) != 0 {
		t.Fatalf("after delete: rows %d remote %+v", len(rows), f.maps[rid])
	}
	su.OnlineName = "app.test"
	_ = e.m.saveStream(ctx, su)
	if err := e.m.onlineDisable(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	e.m.onlineSync(ctx)
	if rows, _ := e.m.onlinePortRows(ctx); len(rows) != 0 {
		t.Fatalf("after name off: rows %d", len(rows))
	}
	if _, errs := e.m.onlinePortsOf(ctx); errs[su.ID] != "port_name_off" {
		t.Fatalf("name off error: %v", errs)
	}
}

// Austragen scheitert (z. B. ipv64 kurz nicht erreichbar): kein neues Mapping fuer denselben Stream, solange das alte
// noch angemeldet ist - sonst ginge seine ID verloren und es bliebe bei ipv64 verwaist.
func TestOnlinePortsDeleteFails(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if res, err := e.m.onlineEnable(ctx, h, 1); err != nil || len(res) != 1 || res[0].Result != "on" {
		t.Fatalf("enable: %v %+v", err, res)
	}
	st := &Stream{Name: "Spiel", Enabled: true, ListenPort: freePort(t), TCP: true, TargetHost: "127.0.0.1", TargetPort: 9, OnlineName: "app.test"}
	if err := e.m.saveStream(ctx, st); err != nil {
		t.Fatal(err)
	}
	rows, _ := e.m.onlinePortRows(ctx)
	list, _ := e.m.onlineNames(ctx)
	rid := list[0].RemoteID
	if len(rows) != 1 || len(f.maps[rid]) != 1 {
		t.Fatalf("mapping: rows %+v remote %+v", rows, f.maps[rid])
	}
	old := rows[0].MappingID
	f.mu.Lock()
	f.delErr = &ipv64api.APIError{Status: 503, Code: "unavailable"}
	f.mu.Unlock()
	st.ListenPort = freePort(t)
	if err := e.m.saveStream(ctx, st); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	n := len(f.maps[rid])
	f.mu.Unlock()
	if rows, _ := e.m.onlinePortRows(ctx); len(rows) != 1 || rows[0].MappingID != old || n != 1 {
		t.Fatalf("delete failed: rows %+v remote %d", rows, n)
	}
	f.mu.Lock()
	f.delErr = nil
	f.mu.Unlock()
	e.m.onlinePortsNow(ctx)
	f.mu.Lock()
	remote := append([]ipv64api.CDN64Mapping(nil), f.maps[rid]...)
	f.mu.Unlock()
	rows, _ = e.m.onlinePortRows(ctx)
	if len(rows) != 1 || rows[0].MappingID == old || rows[0].TargetPort != st.ListenPort || len(remote) != 1 || remote[0].ID != rows[0].MappingID {
		t.Fatalf("after retry: rows %+v remote %+v", rows, remote)
	}
}
