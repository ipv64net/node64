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

// pipeStream: Ende von net.Pipe als Tunnel-Stream.
type pipeStream struct{ net.Conn }

func (pipeStream) CloseWrite() error { return nil }

// Host "nur Streams": nur der Name (kein Ziel, kein Zertifikat), CDN64 nur Modus 1, ueber den Tunnel kein HTTP/HTTPS,
// der Portmapper eines Streams geht ueber den Namen.
func TestStreamOnlyHost(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)

	bad := newHostKind(KindStream)
	bad.Names = []string{"*.game.test"}
	var fe *FieldError
	if err := e.m.saveHost(ctx, bad); !errors.As(err, &fe) || fe.Key != "cdn64.err.stream_wildcard" {
		t.Fatalf("wildcard: %v", err)
	}
	h := newHostKind(KindStream)
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.AccessListID = []string{"game.test"}, "10.0.0.1", 80, CertAuto, 3
	h.Advanced.GeoMode, h.Advanced.GeoCountries = "block", []string{"CN"}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	got, err := e.m.host(ctx, h.ID)
	if err != nil || got.Kind != KindStream || got.TargetHost != "" || got.TargetPort != 0 || got.CertID != CertNone || got.AccessListID != 0 ||
		got.Advanced.GeoMode != "" || got.HTTPS() || firstURL(got) != "" {
		t.Fatalf("stored: %v %+v", err, got)
	}
	e.m.apply(ctx)
	if !e.m.isStreamOnly("GAME.test:443") || e.m.isStreamOnly("other.test") {
		t.Fatal("stream-only names not known")
	}
	if running(e.edge, "http") || running(e.edge, "https") || len(e.edge.Status().Names) != 0 { // keine Route: 80/443 bleiben zu
		t.Fatal("edge listens for a stream-only host")
	}

	if _, err := e.m.onlineEnable(ctx, h, 2); onlineCode(err) != "mode2_stream" {
		t.Fatalf("mode 2: %v", err)
	}
	if res, err := e.m.onlineEnable(ctx, h, 1); err != nil || len(res) != 1 || res[0].Result != "on" {
		t.Fatalf("enable: %v %+v", err, res)
	}

	// ueber den Tunnel: 443, 80, Modus 2 und QUIC werden ohne Antwort geschlossen, gezaehlt fuer den Selbsttest
	visitor := "198.51.100.7:40000"
	for _, kind := range []string{tunnel.KindTLS, tunnel.KindHTTP80, tunnel.KindHTTP, tunnel.KindQUIC} {
		before := e.m.onlineSeenCount("game.test")
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			e.m.onlineHandle(pipeStream{b}, tunnel.Header{Kind: kind, Host: "game.test", Port: 443, Client: visitor})
			close(done)
		}()
		_ = a.SetDeadline(time.Now().Add(3 * time.Second))
		go func() { _, _ = io.WriteString(a, "GET / HTTP/1.1\r\nHost: game.test\r\n\r\n") }()
		if n, err := a.Read(make([]byte, 64)); n != 0 || err == nil {
			t.Fatalf("%s: answered (%d, %v)", kind, n, err)
		}
		a.Close()
		<-done
		if e.m.onlineSeenCount("game.test") != before+1 {
			t.Fatalf("%s: not counted", kind)
		}
	}

	// Stream ueber den Namen: Portmapper angemeldet, TCP aus dem Tunnel kommt am Ziel an
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
	_, tport, _ := net.SplitHostPort(tl.Addr().String())
	sp := freePort(t)
	st := &Stream{Name: "Spiel", Enabled: true, ListenPort: sp, TCP: true, TargetHost: "127.0.0.1", OnlineName: "game.test"}
	st.TargetPort, _ = strconv.Atoi(tport)
	if err := e.m.saveStream(ctx, st); err != nil {
		t.Fatal(err)
	}
	if rows, _ := e.m.onlinePortRows(ctx); len(rows) != 1 || rows[0].Name != "game.test" {
		t.Fatalf("mapping: %+v", rows)
	}
	a, b := net.Pipe()
	go e.m.onlineHandle(pipeStream{b}, tunnel.Header{Kind: tunnel.KindTCP, Host: "game.test", Port: sp, Client: visitor})
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = a.Write([]byte("hi"))
	out, _ := io.ReadAll(a)
	a.Close()
	if string(out) != "T:hi" {
		t.Fatalf("tcp via tunnel: %q", out)
	}

	// Oberflaeche: eine Tabelle - Name mit CDN64 (Dialog nur Modus 1 ohne Healthcheck), darunter seine Ports
	rows, err := e.m.rowsOf(ctx, KindStream)
	if err != nil || len(rows) != 1 || rows[0].Online == nil {
		t.Fatalf("rows: %v %+v", err, rows)
	}
	srows, _ := e.m.streamRows(ctx)
	d := streamsData{Streams: srows, OnlineOn: true}
	d.Names, d.Local = groupStreams(rows, srows)
	if len(d.Names) != 1 || len(d.Names[0].Streams) != 1 || len(d.Local) != 0 {
		t.Fatalf("groups: %+v local %d", d.Names, len(d.Local))
	}
	page := renderPage(t, "streams.html", d)
	for _, want := range []string{`data-stream-name="` + strconv.FormatInt(h.ID, 10) + `"`, "cdn64.streams.name_badge", `data-c64o-test="` + strconv.FormatInt(h.ID, 10) + `"`,
		"data-online-stream", "cdn64.streamnames.list_hint", "/cdn64/streams/new?online_name=game.test", `<span class="font-monospace">` + strconv.Itoa(sp) + `</span>`} {
		if !strings.Contains(page, want) {
			t.Fatalf("streams page misses %s", want)
		}
	}
	for _, not := range []string{`<option value="2">`, "data-online-hc", "cdn64.streams.group_local", "data-c64o-prot"} {
		if strings.Contains(page, not) {
			t.Fatalf("streams page must not have %s", not)
		}
	}
	if strings.Index(page, `data-stream-name=`) > strings.Index(page, `<span class="font-monospace">`+strconv.Itoa(sp)+`</span>`) {
		t.Fatal("port is not listed under its name")
	}
	// Stream ohne eigenen Namen: eigene Gruppe darunter
	d.Names, d.Local = groupStreams(rows, append(srows, streamRow{Stream: &Stream{ID: 99, ListenPort: 1234, TCP: true, Enabled: true, TargetHost: "10.0.0.2", TargetPort: 22}}))
	if page := renderPage(t, "streams.html", d); !strings.Contains(page, "cdn64.streams.group_local") || !strings.Contains(page, ">1234<") {
		t.Fatal("local stream group missing")
	}
	form := aiRender(t, "host_form.html", e.m.form(ctx, got, false))
	if !strings.Contains(form, "data-stream-hint") || strings.Contains(form, `id="tab-ssl"`) || strings.Contains(form, `name="target_host"`) ||
		strings.Contains(form, `name="geo_mode"`) {
		t.Fatal("host form for streams only shows more than name and switch")
	}
	if listPath(KindStream) != "/cdn64/streams" {
		t.Fatalf("back to %s", listPath(KindStream))
	}
}
