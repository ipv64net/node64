package tunnel

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
)

// QUIC-Datagramme (RFC 9221) fuer KindQUIC: Die QUIC-Pakete eines HTTP/3-Besuchers gehen einzeln als Datagramm durch
// den Tunnel statt im Stream. Ein Stream liefert lueckenlos und in Reihenfolge - ein verlorenes Paket haelt alle
// folgenden auf, und der Besucher haelt das fuer Stau (Upload bricht ein). Datagramme gehen verloren wie UDP, der
// Besucher wiederholt selbst. Der Stream bleibt fuer Kopf, Ende und zu grosse Pakete.
//
// Ablauf: Der Server legt je Besucher einen Fluss mit Nummer an (Header.Flow) und schickt zuerst ueber den Stream.
// Die Node antwortet ueber Datagramme, sobald sie den Fluss kennt; erst dann schickt auch der Server Datagramme
// (Answered). Alte Nodes kennen Flow nicht und bleiben beim Stream.

// Datagramm im Tunnel: 4 Byte Fluss-Nummer, dann das Paket des Besuchers.
const dgHeader = 4

var dgSent, dgRecv, dgTooLarge atomic.Uint64

// DatagramCounts: Zaehler seit dem Start (fuer Tests und Metriken).
type DatagramCounts struct {
	Sent, Received, TooLarge uint64 // TooLarge: zu gross fuer ein Datagramm, ueber den Stream geschickt
}

// DatagramStats liefert die Zaehler aller Fluesse.
func DatagramStats() DatagramCounts {
	return DatagramCounts{Sent: dgSent.Load(), Received: dgRecv.Load(), TooLarge: dgTooLarge.Load()}
}

// dgMux verteilt die Datagramme einer QUIC-Verbindung auf die Fluesse.
type dgMux struct {
	s     *quicSession
	mu    sync.Mutex
	flows map[uint32]*DatagramFlow
	next  uint32
	run   bool
}

// DatagramFlow ist der Datagramm-Kanal eines Besuchers.
type DatagramFlow struct {
	m        *dgMux
	id       uint32
	recv     func([]byte)
	answered atomic.Bool
	once     sync.Once
}

// datagrams: Verteiler der Verbindung (nil = eine Seite kann keine Datagramme).
func (s *quicSession) datagrams() *dgMux {
	st := s.c.ConnectionState()
	if !st.SupportsDatagrams.Local || !st.SupportsDatagrams.Remote {
		return nil
	}
	s.dgOnce.Do(func() { s.dg = &dgMux{s: s, flows: map[uint32]*DatagramFlow{}} })
	return s.dg
}

// add legt einen Fluss an (id 0 = naechste freie Nummer; false = Nummer belegt).
func (m *dgMux) add(id uint32, recv func([]byte)) *DatagramFlow {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id == 0 {
		for {
			m.next++
			if m.next != 0 && m.flows[m.next] == nil {
				break
			}
		}
		id = m.next
	} else if m.flows[id] != nil {
		return nil
	}
	f := &DatagramFlow{m: m, id: id, recv: recv}
	m.flows[id] = f
	if !m.run {
		m.run = true
		go m.loop()
	}
	return f
}

// loop liest die Datagramme der Verbindung, bis sie endet (recv darf nicht lange blockieren).
func (m *dgMux) loop() {
	c := m.s.c
	for {
		b, err := c.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if len(b) < dgHeader {
			continue
		}
		m.mu.Lock()
		f := m.flows[binary.BigEndian.Uint32(b)]
		m.mu.Unlock()
		if f == nil {
			continue
		}
		dgRecv.Add(1)
		f.answered.Store(true)
		if f.recv != nil {
			f.recv(b[dgHeader:])
		}
	}
}

// ID ist die Nummer fuer Header.Flow.
func (f *DatagramFlow) ID() uint32 { return f.id }

// Answered: die Gegenseite hat schon ein Datagramm dieses Flusses geschickt (kennt ihn also).
func (f *DatagramFlow) Answered() bool { return f.answered.Load() }

// Send schickt p als Datagramm; false = nicht geschickt (zu gross, Verbindung zu) - dann ueber den Stream.
func (f *DatagramFlow) Send(p []byte) bool {
	b := make([]byte, dgHeader+len(p))
	binary.BigEndian.PutUint32(b, f.id)
	copy(b[dgHeader:], p)
	if err := f.m.s.c.SendDatagram(b); err != nil {
		dgTooLarge.Add(1)
		return false
	}
	dgSent.Add(1)
	return true
}

// Close meldet den Fluss ab (spaetere Datagramme mit seiner Nummer werden verworfen).
func (f *DatagramFlow) Close() {
	f.once.Do(func() {
		f.m.mu.Lock()
		if f.m.flows[f.id] == f {
			delete(f.m.flows, f.id)
		}
		f.m.mu.Unlock()
	})
}

// sessionOf: QUIC-Session hinter einem Stream (nil = TCP-Ausweichweg oder fremder Stream).
func sessionOf(st Stream) *quicSession {
	for {
		switch s := st.(type) {
		case *quicStream:
			return s.qs
		case *countedStream:
			st = s.Stream
		default:
			return nil
		}
	}
}

// AcceptDatagrams (Node): Datagramm-Fluss mit der Nummer aus dem Kopf des Streams; nil = keine Datagramme (dann nur
// der Stream). recv bekommt jedes Paket des Besuchers und darf nicht lange blockieren.
func AcceptDatagrams(st Stream, id uint32, recv func([]byte)) *DatagramFlow {
	if id == 0 {
		return nil
	}
	qs := sessionOf(st)
	if qs == nil {
		return nil
	}
	m := qs.datagrams()
	if m == nil {
		return nil
	}
	return m.add(id, recv)
}
