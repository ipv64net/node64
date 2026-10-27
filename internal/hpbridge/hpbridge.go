// Package hpbridge verbindet PROXY64 (internal/cdn64) und Honeypot64 (internal/honeypot) innerhalb einer Node, ohne
// dass die beiden Pakete sich gegenseitig kennen. Alles ist Opt-in: Was PROXY64 davon nutzt, steht in den
// Einstellungen von PROXY64 (je Punkt ein Schalter, Standard aus); Honeypot64 meldet sich hier nur an, solange das
// Modul laeuft.
//
// Drei Wege (Plan docs/PLAN-NODE64-HONEYPOT64.md, „PROXY64 und Honeypot64“):
//  1. Koeder: Anfragen ohne passenden Host (nur IP, fremde Domain, leere SNI) gibt PROXY64 an den Web-Koeder des
//     Honeypots statt eine Fehlerseite zu liefern (Decoy).
//  2. Zugriffe: PROXY64 gibt jeden Zugriff (nur Metadaten) an den Log-Sensor des Honeypots, der ihn mit eigenen
//     Regeln auswertet (Access). Inhalte der Seiten werden nie weitergegeben, gemeldet wird wie bei echten Logs
//     nur IP, Art, Anzahl.
//  3. Sofort-Sperre: Faellt eine IP im Honeypot auf (Falle oder Regel aus 2), meldet er sie hier (PublishBlock);
//     PROXY64 sperrt sie lokal fuer eine Weile (SubscribeBlocks), ohne auf die v64 Blocklist zu warten. Die Sperre
//     schaltet PROXY64 selbst oder Honeypot64 (SetBlockWanted, Standard an: auch ohne Meldung an ipv64 schuetzt der
//     Honeypot so den eigenen Proxy).
package hpbridge

import (
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Access ist ein Zugriff auf PROXY64 (nur Metadaten).
type Access struct {
	Time     time.Time
	Src      netip.Addr // Client (nach Trusted Proxies)
	Host     string     // angefragter Host (klein)
	Known    bool       // Host gehoert zu einem eingerichteten Host
	Method   string
	Path     string // ohne Abfrage
	Status   int
	TLS      bool
	AuthFail bool   // Anmeldung am vorgeschalteten Login (SSO/Forward-Auth) abgelehnt
	UA       string // nur fuer die Einordnung (bekannte Scanner), wird nicht gemeldet
}

// Block ist eine IP, die lokal gesperrt werden soll.
type Block struct {
	IP     netip.Addr
	Reason string    // Art, z. B. "ssh:bruteforce", "http:exploit:traversal"
	Until  time.Time // Ende der Sperre
}

var (
	decoy  atomic.Pointer[http.Handler]
	access atomic.Pointer[func(Access)]
	wanted atomic.Bool
	block  atomic.Bool // Honeypot64 moechte die Sofort-Sperre

	subMu sync.Mutex
	subs  = map[int]func(Block){}
	subN  int
)

// SetDecoy meldet den Web-Koeder an (nil = abmelden). Nur Honeypot64.
func SetDecoy(h http.Handler) {
	if h == nil {
		decoy.Store(nil)
		return
	}
	decoy.Store(&h)
}

// Decoy liefert den Web-Koeder oder nil (Honeypot aus). Nur PROXY64.
func Decoy() http.Handler {
	if p := decoy.Load(); p != nil {
		return *p
	}
	return nil
}

// SetAccessSink meldet die Auswertung der Zugriffe an (nil = abmelden). Nur Honeypot64; f muss schnell zurueckkehren.
func SetAccessSink(f func(Access)) {
	if f == nil {
		access.Store(nil)
		return
	}
	access.Store(&f)
}

// SetWanted: der Honeypot laeuft „nur ueber PROXY64“ (Vorlage proxy, keine eigenen Ports) und moechte die
// unzuordenbaren und als schaedlich erkannten Anfragen bekommen. Nur Honeypot64.
func SetWanted(on bool) { wanted.Store(on) }

// Wanted: der Honeypot moechte den Verkehr von PROXY64 (dann gilt der Koeder als eingeschaltet). Nur PROXY64.
func Wanted() bool { return wanted.Load() && Decoy() != nil }

// SetBlockWanted: Honeypot64 moechte, dass PROXY64 auffaellige IPs lokal sperrt (Schalter im Honeypot). Nur
// Honeypot64.
func SetBlockWanted(on bool) { block.Store(on) }

// BlockWanted: der Honeypot laeuft und moechte die Sofort-Sperre (gilt dann als eingeschaltet). Nur PROXY64.
func BlockWanted() bool { return block.Load() }

// Blockers: es gibt eine Abonnentin der Sperren (PROXY64 laeuft). Nur fuer die Anzeige im Honeypot.
func Blockers() bool {
	subMu.Lock()
	defer subMu.Unlock()
	return len(subs) > 0
}

// AccessActive: es gibt eine Auswertung (PROXY64 kann sich sonst die Arbeit sparen).
func AccessActive() bool { return access.Load() != nil }

// Report gibt einen Zugriff weiter (tut nichts ohne Auswertung). Nur PROXY64.
func Report(a Access) {
	if p := access.Load(); p != nil {
		(*p)(a)
	}
}

// PublishBlock meldet eine IP zur lokalen Sperre an alle Abonnenten. Nur Honeypot64.
func PublishBlock(b Block) {
	subMu.Lock()
	list := make([]func(Block), 0, len(subs))
	for _, f := range subs {
		list = append(list, f)
	}
	subMu.Unlock()
	for _, f := range list {
		f(b)
	}
}

// SubscribeBlocks abonniert Sperren; die Funktion beendet das Abo. Nur PROXY64; f muss schnell zurueckkehren.
func SubscribeBlocks(f func(Block)) (cancel func()) {
	subMu.Lock()
	subN++
	id := subN
	subs[id] = f
	subMu.Unlock()
	return func() {
		subMu.Lock()
		delete(subs, id)
		subMu.Unlock()
	}
}
