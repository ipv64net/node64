package cdn64

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// Bandbreite je Proxy-Host (Advanced.BWDownMbit/BWUpMbit) bzw. je Stream (Stream.BWDownMbit/BWUpMbit), 0 = unbegrenzt: alle Anfragen eines Hosts teilen sich
// je Richtung einen Token-Eimer. Bis zur Grenze laeuft alles normal, darueber wartet jede Anfrage auf ihren Anteil
// (Warteschlange) - getrennt wird nichts. Gilt fuer Antworten, Uploads und uebernommene Verbindungen (WebSocket),
// lokal wie ueber CDN64.

const bwMaxMbit = 100000 // hoechstens 100 Gbit/s je Richtung

// bwPair: Grenzen eines Hosts (bleiben ueber das Neu-Anmelden der Routen erhalten, damit laufende Anfragen sie teilen).
type bwPair struct{ down, up *rate.Limiter }

type bwSet struct {
	mu sync.Mutex
	m  map[int64]*bwPair
}

// of: Grenzen des Hosts auf den Stand der Einstellung bringen; nil = in beide Richtungen unbegrenzt.
func (s *bwSet) of(id int64, downMbit, upMbit int) *bwPair {
	s.mu.Lock()
	defer s.mu.Unlock()
	if downMbit <= 0 && upMbit <= 0 {
		if p := s.m[id]; p != nil { // laufende Anfragen sofort ohne Grenze
			bwSetLimit(p.down, 0)
			bwSetLimit(p.up, 0)
		}
		delete(s.m, id)
		return nil
	}
	if s.m == nil {
		s.m = map[int64]*bwPair{}
	}
	p := s.m[id]
	if p == nil {
		p = &bwPair{down: rate.NewLimiter(rate.Inf, 0), up: rate.NewLimiter(rate.Inf, 0)}
		s.m[id] = p
	}
	bwSetLimit(p.down, downMbit)
	bwSetLimit(p.up, upMbit)
	return p
}

// keep vergisst Grenzen geloeschter Hosts.
func (s *bwSet) keep(list []*Host) {
	ids := make(map[int64]bool, len(list))
	for _, h := range list {
		ids[h.ID] = true
	}
	s.keepIDs(ids)
}

// keepIDs vergisst Grenzen aller anderen Kennungen (Streams: die laufenden).
func (s *bwSet) keepIDs(ids map[int64]bool) {
	s.mu.Lock()
	for id := range s.m {
		if !ids[id] {
			delete(s.m, id)
		}
	}
	s.mu.Unlock()
}

// bwSetLimit: Mbit/s -> Bytes je Sekunde; Eimer etwa 1/10 s, mindestens 16 KiB, hoechstens 1 MiB.
func bwSetLimit(l *rate.Limiter, mbit int) {
	if mbit <= 0 {
		l.SetLimit(rate.Inf)
		return
	}
	bps := float64(mbit) * 1e6 / 8
	l.SetBurst(min(max(int(bps/10), 16<<10), 1<<20))
	l.SetLimit(rate.Limit(bps))
}

// bwTake wartet auf hoechstens n Bytes (eine Eimergroesse) und liefert, wie viele es waren. Aendert sich die Grenze
// gerade (kleinerer Eimer, unbegrenzt), wird neu gerechnet statt abgebrochen.
func bwTake(ctx context.Context, l *rate.Limiter, n int) (int, error) {
	for {
		if l == nil || l.Limit() == rate.Inf {
			return n, nil
		}
		k := min(n, l.Burst())
		err := l.WaitN(ctx, k)
		if err == nil || ctx.Err() != nil || k <= l.Burst() && l.Limit() != rate.Inf {
			return k, err
		}
	}
}

// bwWait: auf n Bytes warten (in Stuecken bis zur Eimergroesse); nil bzw. unbegrenzt = sofort.
func bwWait(ctx context.Context, l *rate.Limiter, n int) error {
	for n > 0 {
		k, err := bwTake(ctx, l, n)
		if err != nil {
			return err
		}
		n -= k
	}
	return nil
}

// bwWrite schreibt p in Stuecken, jedes erst nach seinem Anteil an der Bandbreite.
func bwWrite(ctx context.Context, l *rate.Limiter, w io.Writer, p []byte) (int, error) {
	if l == nil || l.Limit() == rate.Inf {
		return w.Write(p)
	}
	done := 0
	for done < len(p) {
		k, err := bwTake(ctx, l, len(p)-done)
		if err != nil {
			return done, err
		}
		n, err := w.Write(p[done : done+k])
		done += n
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

// bwRead liest hoechstens eine Eimergroesse und wartet danach auf den Anteil (Upload; bremst den Besucher ueber TCP).
func bwRead(ctx context.Context, l *rate.Limiter, r io.Reader, p []byte) (int, error) {
	if l != nil && l.Limit() != rate.Inf && len(p) > l.Burst() {
		p = p[:l.Burst()]
	}
	n, err := r.Read(p)
	if n > 0 {
		if werr := bwWait(ctx, l, n); werr != nil && err == nil {
			err = werr
		}
	}
	return n, err
}

// bwConn: uebernommene Verbindung (WebSocket) mit den Grenzen des Hosts.
type bwConn struct {
	net.Conn
	bw *bwPair
}

func (c *bwConn) Read(p []byte) (int, error) {
	return bwRead(context.Background(), c.bw.up, c.Conn, p)
}

func (c *bwConn) Write(p []byte) (int, error) {
	return bwWrite(context.Background(), c.bw.down, c.Conn, p)
}

// CloseWrite: halb schliessen wie die Verbindung darunter (Streams, edge.Pipe).
func (c *bwConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// bwBody: Request-Body (Upload) mit der Grenze des Hosts.
type bwBody struct {
	io.ReadCloser
	ctx context.Context
	l   *rate.Limiter
	n   *atomic.Int64 // wie countBody: gelesene Bytes
}

func (b *bwBody) Read(p []byte) (int, error) {
	n, err := bwRead(b.ctx, b.l, b.ReadCloser, p)
	b.n.Add(int64(n))
	return n, err
}
