package upstream

import (
	"context"
	"sort"
	"time"

	"github.com/miekg/dns"
)

// Betriebsart "fastest": Jede Anfrage geht nur an die gerade schnellsten Upstreams (Standard 2) gleichzeitig,
// die erste gute Antwort gewinnt. Die Rangfolge ergibt sich laufend aus den echten Antwortzeiten; Upstreams,
// die gerade nicht gefragt werden, misst ein kleiner Test alle 30 s nach (eine Anfrage je Server). So bleibt
// die Auswahl aktuell, ohne jede Anfrage an alle zu schicken. Antwortet keiner der ersten rechtzeitig, kommt
// der naechste dazu; scheitern alle, werden die uebrigen gefragt.

const (
	DefaultTop = 2 // so viele Upstreams fragt "fastest" gleichzeitig
	MaxTop     = 3

	probeEvery = 30 * time.Second
	minHedge   = 300 * time.Millisecond
	maxHedge   = 1500 * time.Millisecond
)

// SetTop setzt, wie viele Upstreams "fastest" gleichzeitig fragt (1..MaxTop).
func (r *Resolver) SetTop(n int) {
	r.top = max(1, min(n, MaxTop))
}

// Top: so viele fragt "fastest" gleichzeitig.
func (r *Resolver) Top() int { return r.top }

type rankItem struct {
	u       *doh
	ms      float64
	healthy bool
	known   bool
}

// ranked: gesunde mit Messwert nach Antwortzeit, dann noch ungemessene, zuletzt gestoerte (laengster Fehler
// zuerst, er hatte am meisten Zeit sich zu erholen).
func (r *Resolver) ranked() []*doh {
	items := make([]rankItem, 0, len(r.ups))
	for _, u := range r.ups {
		u.mu.Lock()
		it := rankItem{u: u, ms: u.recentMs, known: !u.lastOKAt.IsZero(), healthy: u.lastErrAt.IsZero() || u.lastOKAt.After(u.lastErrAt)}
		errAt := u.lastErrAt
		u.mu.Unlock()
		if !it.healthy {
			it.ms = float64(errAt.UnixMilli()) // aelterer Fehler zuerst
		}
		items = append(items, it)
	}
	class := func(it rankItem) int {
		switch {
		case !it.healthy:
			return 2
		case !it.known:
			return 1
		}
		return 0
	}
	sort.SliceStable(items, func(i, j int) bool {
		ci, cj := class(items[i]), class(items[j])
		if ci != cj {
			return ci < cj
		}
		if ci == 1 {
			return false // ungemessene in der eingestellten Reihenfolge
		}
		return items[i].ms < items[j].ms
	})
	out := make([]*doh, len(items))
	for i, it := range items {
		out[i] = it.u
	}
	return out
}

// first: die Upstreams, die "fastest" zuerst fragt.
func (r *Resolver) first() []*doh {
	rank := r.ranked()
	return rank[:min(r.top, len(rank))]
}

func (r *Resolver) exchangeFastest(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	rank := r.ranked()
	k := min(r.top, len(rank))
	return r.race(ctx, req, rank[:k], rank[k:], hedgeDelay(rank[0]))
}

// hedgeDelay: so lange warten, bevor der naechste dazukommt (das Vierfache der ueblichen Antwortzeit des
// Schnellsten, mindestens 300 ms, hoechstens 1,5 s; ungemessen 1,5 s).
func hedgeDelay(u *doh) time.Duration {
	u.mu.Lock()
	ms := u.recentMs
	u.mu.Unlock()
	if ms <= 0 {
		return maxHedge
	}
	return min(max(time.Duration(4*ms*float64(time.Millisecond)), minHedge), maxHedge)
}

// RunProbes misst in der Betriebsart "fastest" alle 30 s die Upstreams nach, die in dieser Zeit nicht gefragt
// wurden (gleich beim Start alle). Endet mit ctx; in den anderen Betriebsarten sofort.
func (r *Resolver) RunProbes(ctx context.Context) {
	if r.mode != ModeFastest || len(r.ups) <= r.top {
		return
	}
	r.probe(ctx, time.Time{}, false) // Verbindungen aufbauen (Handshake verfaelscht sonst die Rangfolge)
	r.probe(ctx, time.Time{}, true)
	t := time.NewTicker(probeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.probe(ctx, now.Add(-probeEvery), true)
		}
	}
}

// probe fragt jeden Upstream, der seit since nicht gefragt wurde, einmal nach ". NS" (beim Anbieter immer im
// Cache: gemessen wird der Weg dorthin) und wartet auf alle. Ohne measure zaehlen nur Fehler.
func (r *Resolver) probe(ctx context.Context, since time.Time, measure bool) {
	done := make(chan struct{}, len(r.ups))
	n := 0
	for _, u := range r.ups {
		u.mu.Lock()
		skip := !since.IsZero() && u.lastUsed.After(since)
		u.mu.Unlock()
		if skip {
			continue
		}
		n++
		go func() {
			defer func() { done <- struct{}{} }()
			q := new(dns.Msg)
			q.SetQuestion(".", dns.TypeNS)
			actx, cancel := context.WithTimeout(ctx, attemptTimeout)
			defer cancel()
			start := time.Now()
			_, err := u.exchange(actx, q)
			if ctx.Err() == nil && (measure || err != nil) {
				u.record(time.Since(start), err, true)
			}
		}()
	}
	for ; n > 0; n-- {
		<-done
	}
}
