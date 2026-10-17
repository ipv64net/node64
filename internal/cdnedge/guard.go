package cdnedge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/shield"
)

// guard: grober Schutz vor der Weitergabe in einen Tunnel (Modus 1 sieht keine Inhalte): ipv64-Blocklisten,
// gleichzeitige und neue Verbindungen je IP (IPv6 je /64), Verbindungen insgesamt. Feineres macht die Node mit der
// echten Besucher-IP.
type guard struct {
	connsPerIP, rate, burst, maxConns int
	mu                                sync.Mutex
	ips                               map[netip.Addr]*gstate
	open                              atomic.Int64
	rejected                          atomic.Int64
	set                               atomic.Pointer[shield.Set]
	now                               func() time.Time
}

type gstate struct {
	conns int
	tok   float64
	at    time.Time
}

func newGuard(c ShieldConfig) *guard {
	def := func(v, d int) int {
		switch {
		case v == 0:
			return d
		case v < 0:
			return 0
		}
		return v
	}
	g := &guard{connsPerIP: def(c.ConnsPerIP, 256), rate: def(c.ConnRate, 50), maxConns: def(c.MaxConns, 50000),
		ips: map[netip.Addr]*gstate{}, now: time.Now}
	g.burst = g.rate * 10
	return g
}

func gkey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

// admit: Verbindung zulassen? release gibt den Platz frei; why ist der Grund einer Abweisung.
func (g *guard) admit(a netip.Addr) (release func(), why string) {
	a = a.Unmap()
	if g.set.Load().Has(a) {
		g.rejected.Add(1)
		return nil, "blocklist"
	}
	if g.maxConns > 0 && g.open.Load() >= int64(g.maxConns) {
		g.rejected.Add(1)
		return nil, "max_conns"
	}
	k, now := gkey(a), g.now()
	g.mu.Lock()
	st := g.ips[k]
	if st == nil {
		st = &gstate{tok: float64(g.burst), at: now}
		g.ips[k] = st
	} else if dt := now.Sub(st.at).Seconds(); dt > 0 {
		st.tok = min(st.tok+dt*float64(g.rate), float64(g.burst))
		st.at = now
	}
	switch {
	case g.connsPerIP > 0 && st.conns >= g.connsPerIP:
		g.mu.Unlock()
		g.rejected.Add(1)
		return nil, "conns"
	case g.rate > 0 && st.tok < 1:
		g.mu.Unlock()
		g.rejected.Add(1)
		return nil, "conn_rate"
	}
	if g.rate > 0 {
		st.tok--
	}
	st.conns++
	g.mu.Unlock()
	g.open.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			st.conns--
			g.mu.Unlock()
			g.open.Add(-1)
		})
	}, ""
}

// sweep raeumt ruhige Adressen weg (jede Minute).
func (g *guard) sweep() {
	now := g.now()
	g.mu.Lock()
	for k, st := range g.ips {
		if st.conns == 0 && now.Sub(st.at) > 2*time.Minute {
			delete(g.ips, k)
		}
	}
	g.mu.Unlock()
}

// ---------------------------------------------------------------- Blocklisten

// blocklistLoop laedt die eingestellten Listen von ipv64.net (alle 30 Minuten, ETag, Zwischenspeicher in data_dir).
func (s *Server) blocklistLoop(ctx context.Context) {
	ids := s.cfg.Shield.Blocklists
	if len(ids) == 0 {
		return
	}
	base := s.cfg.Shield.BlocklistBase
	if base == "" {
		base = "https://ipv64.net/blocklists/"
	}
	dir := filepath.Join(s.cfg.DataDir, "blocklists")
	_ = os.MkdirAll(dir, 0o750)
	client := &http.Client{Timeout: 60 * time.Second}
	nets := map[string][]netip.Prefix{}
	etag := map[string]string{}
	for _, id := range ids { // sofort aus dem Zwischenspeicher
		if f, err := os.Open(filepath.Join(dir, id+".txt")); err == nil {
			nets[id], _ = shield.ParseList(io.LimitReader(f, 32<<20))
			f.Close()
		}
	}
	rebuild := func() {
		var lists [][]netip.Prefix
		for _, id := range ids {
			lists = append(lists, nets[id])
		}
		if set := shield.BuildSet(lists, nil); set.Total() > 0 {
			s.guard.set.Store(set)
		}
	}
	rebuild()
	fetch := func(id string) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"ipv64_blocklist_"+id+".txt", nil)
		if e := etag[id]; e != "" {
			req.Header.Set("If-None-Match", e)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotModified {
			return nil
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: http %d", id, resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return err
		}
		if bytes.Contains(bytes.ToLower(raw[:min(len(raw), 512)]), []byte("<html")) {
			return fmt.Errorf("%s: html instead of list", id)
		}
		list, err := shield.ParseList(bytes.NewReader(raw))
		if err != nil || len(list) == 0 {
			return fmt.Errorf("%s: empty list", id)
		}
		nets[id], etag[id] = list, resp.Header.Get("ETag")
		tmp := filepath.Join(dir, id+".tmp")
		if os.WriteFile(tmp, raw, 0o640) == nil {
			_ = os.Rename(tmp, filepath.Join(dir, id+".txt"))
		}
		return nil
	}
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		for _, id := range ids {
			if err := fetch(id); err != nil && ctx.Err() == nil {
				s.log.Warn("blocklist not loaded", "list", id, "err", err)
			}
		}
		rebuild()
		s.log.Info("blocklists ready", "entries", s.guard.set.Load().Total())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func addrOf(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}
