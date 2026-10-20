package honeypot

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Port-Scan-Erkennung: eine Quelle beruehrt innerhalb von sensorScanWindow mindestens sensorScanPorts verschiedene
// Fallen-Ports -> einmal KindPortScan je Quelle und Zeitfenster (Detail = Ports aufsteigend). Speicher begrenzt
// (sensorScanMax Quellen, je Quelle hoechstens sensorScanKeep Ports), abgelaufene Eintraege werden regelmaessig entfernt.
const (
	sensorScanWindow = 60 * time.Second
	sensorScanPorts  = 4
	sensorScanMax    = 10000
	sensorScanKeep   = 16
)

type sensorScan struct {
	mu    sync.Mutex
	m     map[netip.Addr]*sensorScanEntry
	sweep time.Time // naechstes Aufraeumen
}

type sensorScanEntry struct {
	start time.Time
	ports []int
	done  bool // in diesem Fenster schon gemeldet
}

// touch vermerkt einen Port; liefert die Ports, wenn die Schwelle in diesem Fenster gerade erreicht wurde.
func (sc *sensorScan) touch(src netip.Addr, port int, now time.Time) []int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.m == nil {
		sc.m = map[netip.Addr]*sensorScanEntry{}
	}
	if now.After(sc.sweep) {
		for k, e := range sc.m {
			if now.Sub(e.start) > sensorScanWindow {
				delete(sc.m, k)
			}
		}
		sc.sweep = now.Add(sensorScanWindow)
		if len(sc.m) >= sensorScanMax {
			sc.sweep = now.Add(time.Second) // voll: bald wieder, aber nicht bei jeder Verbindung
		}
	}
	e := sc.m[src]
	if e == nil || now.Sub(e.start) > sensorScanWindow {
		if e == nil && len(sc.m) >= sensorScanMax {
			return nil // voll: neue Quellen erst nach dem Ablauf anderer
		}
		e = &sensorScanEntry{start: now}
		sc.m[src] = e
	}
	for _, p := range e.ports {
		if p == port {
			return nil
		}
	}
	if len(e.ports) < sensorScanKeep {
		e.ports = append(e.ports, port)
	}
	if e.done || len(e.ports) < sensorScanPorts {
		return nil
	}
	e.done = true
	out := append([]int(nil), e.ports...)
	slices.Sort(out)
	return out
}

func (sc *sensorScan) reset() {
	sc.mu.Lock()
	sc.m = nil
	sc.mu.Unlock()
}

// scanTouch meldet einen Port-Scan, sobald eine Quelle genug verschiedene Fallen-Ports beruehrt hat.
func (s *Sensor) scanTouch(t *trapService, src netip.Addr) {
	if !s.scanOn.Load() || !src.IsValid() {
		return
	}
	ports := s.scan.touch(src, t.key.Port, time.Now())
	if ports == nil {
		return
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	s.emit(Event{Time: time.Now(), Service: SvcScan, Port: t.key.Port, Kind: KindPortScan, Src: src, Detail: strings.Join(parts, ",")})
}
