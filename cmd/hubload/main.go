// hubload: Lasttest fuer den ipv64-hub (Rolle gateway). Simuliert viele Nodes.
//
//	hubload gen -n 10000 -checks 10 -prefill 3h -o lt -> lt.tokens, lt.sql (Nodes, Tokens, Checks), lt.csv (Messpunkte)
//	hubload run -url https://hc-srv01.ipv64.net -tokens lt.tokens -rate 200 -interval 60s -duration 10m
//
// Jede simulierte Node verbindet sich per WebSocket, wartet auf hello+config und verhaelt sich wie
// eine echte Node: jeder Check misst im Intervall, Zustaende gehen alle 2 s ("states"), Messpunkte
// gesammelt alle 30 s ("measurements"). Mit -fail stoeren einzelne Checks zeitweise (Stoerungslogik).
// Ausgegeben werden alle 10 s verbundene Nodes, Fehler und die Ack-Latenz (p50/p99).
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
	nChecks := fs.Int("checks", 0, "Checks je Node (0 = keine, wie bisher)")
	prefill := fs.Duration("prefill", 0, "Messpunkte rueckwirkend erzeugen (CSV fuer LOAD DATA)")
	every := fs.Duration("interval", time.Minute, "Messabstand fuer die Vorbefuellung")
	_ = fs.Parse(args)
	var csv *bufio.Writer
	if *prefill > 0 && *nChecks > 0 {
		cf, err := os.Create(*out + ".csv")
		must(err)
		defer cf.Close()
		csv = bufio.NewWriterSize(cf, 1<<20)
		defer csv.Flush()
	}
	tf, err := os.Create(*out + ".tokens")
	must(err)
	sf, err := os.Create(*out + ".sql")
	must(err)
	defer tf.Close()
	defer sf.Close()
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	fmt.Fprintln(sf, "-- hubload: Testnodes; entfernen mit: DELETE FROM hc2_node_tokens WHERE node_id LIKE 'lt%'; DELETE FROM hc2_nodes WHERE node_id LIKE 'lt%';")
	var nodes, toks, chks []string
	flush := func() {
		if len(nodes) > 0 {
			fmt.Fprintf(sf, "INSERT INTO hc2_nodes (userid, node_id, name, location, remote_mgmt, created_at) VALUES %s;\n", strings.Join(nodes, ","))
			fmt.Fprintf(sf, "INSERT INTO hc2_node_tokens (node_id, token_hash, created_at) VALUES %s;\n", strings.Join(toks, ","))
		}
		if len(chks) > 0 {
			fmt.Fprintf(sf, "INSERT INTO hc2_checks (token, userid, node_id, nodes, execution, type, name, target, params, interval_sec, created_at, updated_at) VALUES %s;\n", strings.Join(chks, ","))
		}
		nodes, toks, chks = nodes[:0], toks[:0], chks[:0]
	}
	start := time.Now().UTC().Add(-*prefill)
	for i := 0; i < *n; i++ {
		id := "lt" + randStr(30)
		tok := "node64t_" + randStr(40)
		h := sha256.Sum256([]byte(tok))
		var tokens []string
		for k := 0; k < *nChecks; k++ {
			ct := "lt" + randStr(30)
			tokens = append(tokens, ct)
			chks = append(chks, fmt.Sprintf("('%s',%d,'%s','%s','local','http','loadtest %d','https://example.invalid/','{}',60,'%s','%s')", ct, 900000000+i, id, id, k, now, now))
			if csv != nil {
				// Messpunkte wie von der Node (node_seq laufend je Node)
				for t, seq := start, int64(k+1); t.Before(time.Now().UTC()); t, seq = t.Add(*every), seq+int64(*nChecks) {
					ts := t.Add(time.Duration(k) * time.Second).Format("2006-01-02 15:04:05.000")
					fmt.Fprintf(csv, "%s\tnode:%s\t%d\t%s\t1\t%.1f\tok\t200 OK\tipv4\t\\N\t0\t%s\n", ct, id, seq, ts, 5+mrand.Float64()*40, ts)
				}
			}
		}
		fmt.Fprintf(tf, "%s %s %s\n", id, tok, strings.Join(tokens, ","))
		nodes = append(nodes, fmt.Sprintf("(%d,'%s','loadtest','lasttest','read','%s')", 900000000+i, id, now))
		toks = append(toks, fmt.Sprintf("('%s','%s','%s')", id, hex.EncodeToString(h[:]), now))
		if len(nodes) == 500 {
			flush()
		}
	}
	flush()
	fmt.Printf("%d Nodes mit je %d Checks: %s.tokens, %s.sql (Vorbefuellung %v)\n", *n, *nChecks, *out, *out, *prefill)
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
	interval := fs.Duration("interval", time.Minute, "Messintervall je Check")
	fail := fs.Float64("fail", 0.001, "Anteil der Messungen, mit denen ein Check fuer 3 Messungen stoert")
	duration := fs.Duration("duration", 10*time.Minute, "Laufzeit nach dem Hochfahren")
	_ = fs.Parse(args)

	f, err := os.Open(*tokFile)
	must(err)
	type node struct {
		id, tok string
		checks  []string
	}
	var list []node
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) >= 2 {
			nd := node{id: p[0], tok: p[1]}
			if len(p) == 3 {
				nd.checks = strings.Split(p[2], ",")
			}
			list = append(list, nd)
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
			session(ctx, ws, st, *interval, nd.checks, *fail)
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

// session: hello/config abwarten, dann wie eine echte Node messen, Zustaende und Messpunkte schicken.
func session(ctx context.Context, ws *websocket.Conn, st *stats, interval time.Duration, checks []string, fail float64) {
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
	if len(checks) == 0 {
		checks = []string{"lt" + randStr(30)} // altes Verhalten: ein Messpunkt ohne Check
	}
	var id int64
	request := func(t string, data any) error {
		id++
		d, _ := json.Marshal(data)
		mu.Lock()
		waiting[id] = time.Now()
		mu.Unlock()
		return send(sctx, ws, msg{T: t, ID: id, Data: d})
	}
	// je Check: naechste Messung (gleichmaessig verteilt) und wie viele Messungen er noch stoert
	due := make([]time.Time, len(checks))
	bad := make([]int, len(checks))
	for i := range due {
		due[i] = time.Now().Add(time.Duration(mrand.Int64N(int64(interval))))
	}
	seq := int64(1_000_000_000) + time.Now().Unix()%1_000_000*100
	var pending []map[string]any
	stTick := time.NewTicker(2 * time.Second) // wie die Node: Zustaende alle 2 s
	defer stTick.Stop()
	upTick := time.NewTicker(30 * time.Second) // Messpunkte gesammelt alle 30 s
	defer upTick.Stop()
	for {
		select {
		case <-sctx.Done():
			return
		case <-upTick.C:
			for len(pending) > 0 {
				n := min(len(pending), 500)
				if err := request("measurements", map[string]any{"batch": pending[:n]}); err != nil {
					return
				}
				pending = pending[n:]
			}
		case now := <-stTick.C:
			var states []map[string]any
			for i, tok := range checks {
				if now.Before(due[i]) {
					continue
				}
				due[i] = due[i].Add(interval)
				if bad[i] == 0 && mrand.Float64() < fail {
					bad[i] = 3
				}
				status, state, reason := "up", "up", "ok"
				if bad[i] > 0 {
					bad[i]--
					status, state, reason = "down", "down", "timeout"
				}
				seq++
				pending = append(pending, map[string]any{"seq": seq, "token": tok, "time": now.UTC(), "status": status, "latency_ms": 5 + mrand.Float64()*40, "reason": reason, "message": "loadtest", "family": "ipv4"})
				states = append(states, map[string]any{"token": tok, "state": state, "last_status": status, "latency_ms": 12.5, "reason": reason, "message": "loadtest",
					"since": now.UTC(), "last_check_at": now.UTC(), "next_check_at": due[i].UTC()})
			}
			if len(states) > 0 {
				if err := request("states", map[string]any{"items": states}); err != nil {
					return
				}
			}
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
