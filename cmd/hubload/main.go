// hubload: Lasttest fuer den ipv64-hub (Rolle gateway). Simuliert viele Nodes.
//
//	hubload gen -n 10000 -o lt        -> lt.tokens (node_id token) und lt.sql (Nodes + Tokens anlegen)
//	hubload run -url https://hc-srv01.ipv64.net -tokens lt.tokens -rate 200 -interval 30s -duration 10m
//
// Jede simulierte Node verbindet sich per WebSocket, wartet auf hello+config und schickt
// im Intervall einen Messpunkt (wie eine echte Node). Ausgegeben werden alle 10 s
// verbundene Nodes, Fehler und die Ack-Latenz (p50/p99).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		x, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[x.Int64()]
	}
	return string(b)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hubload gen|run ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		gen(os.Args[2:])
	case "run":
		run(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: hubload gen|run ...")
		os.Exit(2)
	}
}

// gen erzeugt Tokens und das SQL zum Anlegen. Nodes heissen "loadtest", Node-IDs beginnen mit "lt",
// Benutzer-IDs ab 900000000 (gibt es nicht; jede Node hat ihren eigenen Account, damit die Konfiguration klein bleibt).
func gen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	n := fs.Int("n", 1000, "Anzahl Nodes")
	out := fs.String("o", "lt", "Dateipraefix")
	_ = fs.Parse(args)
	tf, err := os.Create(*out + ".tokens")
	must(err)
	sf, err := os.Create(*out + ".sql")
	must(err)
	defer tf.Close()
	defer sf.Close()
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	fmt.Fprintln(sf, "-- hubload: Testnodes; entfernen mit: DELETE FROM hc2_node_tokens WHERE node_id LIKE 'lt%'; DELETE FROM hc2_nodes WHERE node_id LIKE 'lt%';")
	var nodes, toks []string
	flush := func() {
		if len(nodes) > 0 {
			fmt.Fprintf(sf, "INSERT INTO hc2_nodes (userid, node_id, name, location, remote_mgmt, created_at) VALUES %s;\n", strings.Join(nodes, ","))
			fmt.Fprintf(sf, "INSERT INTO hc2_node_tokens (node_id, token_hash, created_at) VALUES %s;\n", strings.Join(toks, ","))
		}
		nodes, toks = nodes[:0], toks[:0]
	}
	for i := 0; i < *n; i++ {
		id := "lt" + randStr(30)
		tok := "node64t_" + randStr(40)
		h := sha256.Sum256([]byte(tok))
		fmt.Fprintf(tf, "%s %s\n", id, tok)
		nodes = append(nodes, fmt.Sprintf("(%d,'%s','loadtest','lasttest','read','%s')", 900000000+i, id, now))
		toks = append(toks, fmt.Sprintf("('%s','%s','%s')", id, hex.EncodeToString(h[:]), now))
		if len(nodes) == 500 {
			flush()
		}
	}
	flush()
	fmt.Printf("%d Nodes: %s.tokens, %s.sql\n", *n, *out, *out)
}

type stats struct {
	connected, ready, dialFail, dropped, acks, ackErr atomic.Int64
	mu                                                sync.Mutex
	lat                                               []time.Duration
}

func (s *stats) addLat(d time.Duration) {
	s.mu.Lock()
	s.lat = append(s.lat, d)
	s.mu.Unlock()
}

func (s *stats) takeLat() []time.Duration {
	s.mu.Lock()
	l := s.lat
	s.lat = nil
	s.mu.Unlock()
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	return l
}

func pct(l []time.Duration, p float64) time.Duration {
	if len(l) == 0 {
		return 0
	}
	return l[int(float64(len(l)-1)*p)]
}

type msg struct {
	T    string          `json:"t"`
	ID   int64           `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	url := fs.String("url", "https://hc-srv01.ipv64.net", "hub")
	tokFile := fs.String("tokens", "lt.tokens", "Token-Datei aus gen")
	n := fs.Int("n", 0, "Anzahl (0 = alle aus der Datei)")
	rate := fs.Int("rate", 100, "neue Verbindungen pro Sekunde")
	interval := fs.Duration("interval", 30*time.Second, "Abstand der Messpunkte je Node")
	duration := fs.Duration("duration", 10*time.Minute, "Laufzeit nach dem Hochfahren")
	_ = fs.Parse(args)

	f, err := os.Open(*tokFile)
	must(err)
	type node struct{ id, tok string }
	var list []node
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) == 2 {
			list = append(list, node{p[0], p[1]})
		}
	}
	f.Close()
	if *n > 0 && *n < len(list) {
		list = list[:*n]
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	wsURL := strings.Replace(strings.Replace(*url, "https://", "wss://", 1), "http://", "ws://", 1) + "/v1/ws?since=0"
	st := &stats{}
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1000}}
	var wg sync.WaitGroup
	start := time.Now()
	var rampDone atomic.Bool

	go func() { // Ausgabe
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				l := st.takeLat()
				fmt.Printf("%s t=%4.0fs verbunden=%d bereit=%d dialfehler=%d abbrueche=%d acks=%d ackfehler=%d ack_p50=%v ack_p99=%v ack_max=%v\n",
					time.Now().Format("15:04:05"), time.Since(start).Seconds(), st.connected.Load(), st.ready.Load(), st.dialFail.Load(), st.dropped.Load(),
					st.acks.Load(), st.ackErr.Load(), pct(l, 0.5).Round(time.Millisecond), pct(l, 0.99).Round(time.Millisecond), pct(l, 1).Round(time.Millisecond))
			}
		}
	}()

	one := func(nd node) {
		defer wg.Done()
		for ctx.Err() == nil {
			dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			ws, _, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Authorization": {"Bearer " + nd.tok}, "User-Agent": {"node64-hubload"}}, CompressionMode: websocket.CompressionDisabled})
			cancel()
			if err != nil {
				st.dialFail.Add(1)
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(5+mrand.IntN(10)) * time.Second):
				}
				continue
			}
			ws.SetReadLimit(1 << 20)
			st.connected.Add(1)
			session(ctx, ws, st, *interval)
			st.connected.Add(-1)
			if ctx.Err() == nil {
				st.dropped.Add(1)
				time.Sleep(time.Duration(1+mrand.IntN(5)) * time.Second)
			}
		}
	}
	tick := time.NewTicker(time.Second / time.Duration(max(1, *rate)))
	for _, nd := range list {
		select {
		case <-ctx.Done():
		case <-tick.C:
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go one(nd)
	}
	tick.Stop()
	rampDone.Store(true)
	fmt.Printf("Hochfahren fertig nach %v (%d Nodes), Laufzeit %v\n", time.Since(start).Round(time.Second), len(list), *duration)
	select {
	case <-ctx.Done():
	case <-time.After(*duration):
	}
	stop()
	wg.Wait()
	fmt.Println("Ende")
}

// session: hello/config abwarten, dann im Intervall Messpunkte schicken und Acks messen.
func session(ctx context.Context, ws *websocket.Conn, st *stats, interval time.Duration) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer ws.Close(websocket.StatusNormalClosure, "")
	var mu sync.Mutex
	waiting := map[int64]time.Time{}
	ready := make(chan struct{})
	var once sync.Once
	go func() {
		defer cancel()
		for {
			_, data, err := ws.Read(sctx)
			if err != nil {
				return
			}
			var m msg
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			switch m.T {
			case "config":
				once.Do(func() { st.ready.Add(1); close(ready) })
				if m.ID > 0 {
					_ = send(sctx, ws, msg{T: "ack", ID: m.ID})
				}
			case "ack":
				mu.Lock()
				t0, ok := waiting[m.ID]
				delete(waiting, m.ID)
				mu.Unlock()
				if ok {
					var a struct {
						Error string `json:"error"`
					}
					_ = json.Unmarshal(m.Data, &a)
					if a.Error != "" {
						st.ackErr.Add(1)
					} else {
						st.acks.Add(1)
						st.addLat(time.Since(t0))
					}
				}
			case "bye":
				return
			}
		}
	}()
	defer func() {
		select {
		case <-ready:
			st.ready.Add(-1)
		default:
		}
	}()
	select {
	case <-sctx.Done():
		return
	case <-ready:
	}
	// erster Messpunkt zufaellig verteilt, damit nicht alle gleichzeitig senden
	jit := time.NewTimer(time.Duration(mrand.Int64N(int64(interval))))
	defer jit.Stop()
	select {
	case <-sctx.Done():
		return
	case <-jit.C:
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var id, seq int64
	tok := "lt" + randStr(30)
	for {
		id++
		seq++
		batch := []map[string]any{{"seq": seq, "token": tok, "time": time.Now().UTC(), "status": "up", "latency_ms": 12.5, "reason": "ok", "message": "loadtest", "family": "ipv4"}}
		d, _ := json.Marshal(map[string]any{"batch": batch})
		mu.Lock()
		waiting[id] = time.Now()
		mu.Unlock()
		if err := send(sctx, ws, msg{T: "measurements", ID: id, Data: d}); err != nil {
			return
		}
		select {
		case <-sctx.Done():
			return
		case <-t.C:
		}
	}
}

func send(ctx context.Context, ws *websocket.Conn, m msg) error {
	b, _ := json.Marshal(m)
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, b)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
