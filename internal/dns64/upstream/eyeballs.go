package upstream

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// Happy Eyeballs (RFC 8305) fuer die Verbindung zu einem Upstream mit mehreren Bootstrap-IPs: IPv6 und IPv4
// abwechselnd (die zuletzt erfolgreiche Familie zuerst, sonst IPv6), der naechste Versuch startet nach 250 ms
// oder sofort, wenn der vorige scheitert; die erste Verbindung gewinnt, spaeter fertige werden geschlossen. So
// kostet eine haengende Familie (IPv6 ohne Route, gesperrtes IPv4) hoechstens 250 ms statt eines Timeouts, und
// ohne IPv6 im Container scheitern die IPv6-Versuche sofort.

const eyeballDelay = 250 * time.Millisecond

// familyOf: 4 oder 6 fuer "ip:port", 0 bei einem Namen.
func familyOf(addr string) int32 {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	a, err := netip.ParseAddr(host)
	switch {
	case err != nil:
		return 0
	case a.Is4() || a.Is4In6():
		return 4
	}
	return 6
}

// interleave sortiert die Adressen abwechselnd nach Familie, prefer zuerst (0 = IPv6 zuerst); die Reihenfolge
// innerhalb einer Familie bleibt.
func interleave(addrs []string, prefer int32) []string {
	var v4, v6, other []string
	for _, a := range addrs {
		switch familyOf(a) {
		case 4:
			v4 = append(v4, a)
		case 6:
			v6 = append(v6, a)
		default:
			other = append(other, a)
		}
	}
	first, second := v6, v4
	if prefer == 4 {
		first, second = v4, v6
	}
	out := make([]string, 0, len(addrs))
	for i := 0; i < len(first) || i < len(second); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(second) {
			out = append(out, second[i])
		}
	}
	return append(out, other...)
}

// happyDial verbindet nach Happy Eyeballs; pref merkt sich die Familie der letzten erfolgreichen Verbindung.
func happyDial[T any](ctx context.Context, addrs []string, pref *atomic.Int32, dial func(context.Context, string) (T, error), drop func(T)) (T, error) {
	var zero T
	addrs = interleave(addrs, pref.Load())
	if len(addrs) == 0 {
		return zero, net.UnknownNetworkError("no address")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c    T
		addr string
		err  error
	}
	ch := make(chan result, len(addrs))
	next, pending := 0, 0
	start := func() {
		a := addrs[next]
		next++
		pending++
		go func() {
			c, err := dial(ctx, a)
			ch <- result{c, a, err}
		}()
	}
	// rest schliesst Verbindungen, die nach dem Gewinner noch fertig werden.
	rest := func(n int) {
		go func() {
			for ; n > 0; n-- {
				if r := <-ch; r.err == nil {
					drop(r.c)
				}
			}
		}()
	}
	start()
	timer := time.NewTimer(eyeballDelay)
	defer timer.Stop()
	var lastErr error
	for pending > 0 {
		select {
		case r := <-ch:
			pending--
			if r.err == nil {
				if f := familyOf(r.addr); f != 0 {
					pref.Store(f)
				}
				rest(pending)
				return r.c, nil
			}
			lastErr = r.err
			if next < len(addrs) {
				start()
				timer.Reset(eyeballDelay)
			}
		case <-timer.C:
			if next < len(addrs) {
				start()
				timer.Reset(eyeballDelay)
			}
		case <-ctx.Done():
			rest(pending)
			return zero, ctx.Err()
		}
	}
	return zero, lastErr
}
