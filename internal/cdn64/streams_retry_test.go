package cdn64

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// Port eines Protokolls belegt: der minuetliche Abgleich versucht nur dieses noch einmal; das offene Protokoll
// und seine Verbindungen bleiben.
func TestStreamRetryKeepsOpenProtocol(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	tl, err := net.Listen("tcp", "127.0.0.1:0") // Ziel: TCP-Echo
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
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	_, tport, _ := net.SplitHostPort(tl.Addr().String())
	sp := freePort(t)
	busy, err := net.ListenPacket("udp", ":"+strconv.Itoa(sp))
	if err != nil {
		t.Fatal(err)
	}
	st := &Stream{Name: "x", Enabled: true, ListenPort: sp, TCP: true, UDP: true, TargetHost: "127.0.0.1"}
	st.TargetPort, _ = strconv.Atoi(tport)
	if err := e.m.saveStream(ctx, st); err != nil {
		busy.Close()
		t.Fatal(err)
	}
	e.m.smu.Lock()
	run := e.m.runs[st.ID]
	e.m.smu.Unlock()
	if run == nil || run.tcp == nil || run.udp != nil || run.errs["udp"] == "" {
		busy.Close()
		t.Fatalf("udp must fail, tcp open: %+v", run)
	}
	ln := run.tcp
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(sp))
	if err != nil {
		busy.Close()
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	echo := func(s string) string {
		_, _ = io.WriteString(c, s)
		b := make([]byte, len(s))
		_, _ = io.ReadFull(c, b)
		return string(b)
	}
	if got := echo("a"); got != "a" {
		t.Fatalf("echo: %q", got)
	}
	// noch belegt: der TCP-Teil bleibt trotzdem
	e.m.applyStreams(ctx)
	if got := echo("b"); got != "b" {
		t.Fatalf("connection cut by retry: %q", got)
	}
	busy.Close()
	e.m.applyStreams(ctx)
	e.m.smu.Lock()
	run2 := e.m.runs[st.ID]
	ok := run2 == run && run.tcp == ln && run.udp != nil && len(run.errs) == 0
	e.m.smu.Unlock()
	if !ok {
		t.Fatalf("after retry: %+v", run2)
	}
	if got := echo("c"); got != "c" {
		t.Fatalf("connection cut after udp opened: %q", got)
	}
	if errs := e.m.streamErrs(st.ID); errs != nil {
		t.Fatalf("errors left: %v", errs)
	}
}
