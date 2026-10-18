// cdn64-load: kleiner Lasttest fuer CDN64 online (HTTP/1.1, HTTP/2, HTTP/3) mit fester Rate oder Vollgas.
// Nur fuer eigene Tests: go build ./cmd/cdn64-load; cdn64-load -url https://name/ -ip 1.2.3.4 -c 20 -d 20s -rate 40
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	url := flag.String("url", "", "Ziel, z. B. https://pfsense.ipv64.de/")
	ip := flag.String("ip", "", "Adresse statt DNS (Server srv07/srv08)")
	conc := flag.Int("c", 10, "gleichzeitige Clients")
	dur := flag.Duration("d", 10*time.Second, "Dauer")
	total := flag.Int("n", 0, "Anfragen insgesamt (0 = nach Dauer)")
	rate := flag.Float64("rate", 0, "Anfragen je Sekunde insgesamt (0 = so schnell wie moeglich)")
	proto := flag.String("proto", "h2", "h1, h2 oder h3")
	fresh := flag.Bool("fresh", false, "je Anfrage eine neue Verbindung")
	flag.Parse()
	if *url == "" {
		flag.Usage()
		os.Exit(2)
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if *ip != "" {
			_, port, _ := net.SplitHostPort(addr)
			addr = net.JoinHostPort(*ip, port)
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
	var rt http.RoundTripper
	switch *proto {
	case "h3":
		rt = &http3.Transport{Dial: func(ctx context.Context, addr string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			if *ip != "" {
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(*ip, port)
			}
			return quic.DialAddr(ctx, addr, tc, qc)
		}}
	default:
		tr := &http.Transport{DialContext: dial, ForceAttemptHTTP2: *proto == "h2", MaxIdleConnsPerHost: *conc, DisableKeepAlives: *fresh}
		if *proto == "h1" {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		rt = tr
	}
	client := &http.Client{Transport: rt, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var (
		mu     sync.Mutex
		lat    []time.Duration
		codes  = map[string]int{}
		bytes  atomic.Int64
		issued atomic.Int64
	)
	tick := make(chan struct{}, *conc)
	stop := time.Now().Add(*dur)
	go func() {
		var t *time.Ticker
		if *rate > 0 {
			t = time.NewTicker(time.Duration(float64(time.Second) / *rate))
		}
		for {
			if *total > 0 && issued.Load() >= int64(*total) || *total == 0 && time.Now().After(stop) {
				close(tick)
				return
			}
			if t != nil {
				<-t.C
			}
			issued.Add(1)
			tick <- struct{}{}
		}
	}()
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range tick {
				t0 := time.Now()
				resp, err := client.Get(*url)
				d := time.Since(t0)
				key := ""
				if err != nil {
					key = "error"
				} else {
					n, _ := io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					bytes.Add(n)
					key = fmt.Sprintf("%d %s", resp.StatusCode, resp.Proto)
				}
				mu.Lock()
				codes[key]++
				if err == nil {
					lat = append(lat, d)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	el := time.Since(start)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p := func(q float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		return lat[min(len(lat)-1, int(q*float64(len(lat))))]
	}
	n := 0
	for _, v := range codes {
		n += v
	}
	fmt.Printf("requests=%d time=%.1fs rate=%.1f/s bytes=%d p50=%v p95=%v p99=%v max=%v\n", n, el.Seconds(), float64(n)/el.Seconds(), bytes.Load(),
		p(0.5).Round(time.Millisecond), p(0.95).Round(time.Millisecond), p(0.99).Round(time.Millisecond), p(1).Round(time.Millisecond))
	keys := make([]string, 0, len(codes))
	for k := range codes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-14s %d\n", k, codes[k])
	}
}
