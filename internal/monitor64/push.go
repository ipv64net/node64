package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/transport"
	"github.com/ipv64net/node64/internal/ports"
)

// Push-Betrieb des Agents (Plan Phase 3): Hosts hinter NAT bzw. VPS bauen die Verbindung selbst zur Node auf
// (transport.PushListener). Nur die TCP-Richtung dreht sich: der Agent bleibt SSH-Server und prueft die Node ueber
// keys, die Node pinnt seinen Hostschluessel. Der Token im Installationsbefehl ist der Wegweiser zum Zugang (gibt
// keinen Zugriff, ist aber wie ein Geheimnis zu behandeln, siehe transport/push.go).

const (
	setPushPort = "monitor64.push_port" // TCP-Port des Lauschers (Standard m64proto.DefaultPushPort)
	setPushBind = "monitor64.push_bind" // Adresse des Lauschers (leer = alle)
)

// pushPortState: Port-Verzeichnis des Kerns (SetPorts) und letzter Fehler beim Oeffnen, je Modul.
type pushPortState struct {
	mu   sync.Mutex
	reg  *ports.Registry
	want bool   // ein Zugang braucht den Lauscher
	port int    // eingestellter Port (fuer die Anzeige, wenn er nicht offen ist)
	bind string //
	err  string // warum nicht offen
}

// pushPorts haelt pushPortState je Modul (Schluessel *Module).
var pushPorts sync.Map

func (m *Module) pushState() *pushPortState {
	v, _ := pushPorts.LoadOrStore(m, &pushPortState{})
	return v.(*pushPortState)
}

// SetPorts setzt das Port-Verzeichnis des Kerns: der Push-Port wird vor dem Oeffnen gegen die Ports der anderen
// Teile geprueft (Anmeldung mit portReg.Provide(monitor64.Name, m.PushClaims)).
func (m *Module) SetPorts(r *ports.Registry) {
	ps := m.pushState()
	ps.mu.Lock()
	ps.reg = r
	ps.mu.Unlock()
}

// PushClaims liefert den Port des Lauschers fuer das Port-Verzeichnis: offen (aktiv) bzw. gebraucht, aber nicht
// offen (mit Fehler); ohne Push-Zugang keinen.
func (m *Module) PushClaims(context.Context) []ports.Claim {
	m.mu.Lock()
	pl := m.push
	m.mu.Unlock()
	var out []ports.Claim
	if pl != nil {
		for _, a := range pl.Listening() {
			if ta, ok := a.(*net.TCPAddr); ok {
				bind := ""
				if !ta.IP.IsUnspecified() {
					bind = ta.IP.String()
				}
				out = append(out, ports.Claim{Owner: Name, Purpose: "Monitor64 Push", Proto: ports.TCP, Port: ta.Port, Bind: bind, Active: true})
			}
		}
	}
	ps := m.pushState()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if len(out) == 0 && ps.want && pl != nil {
		out = append(out, ports.Claim{Owner: Name, Purpose: "Monitor64 Push", Proto: ports.TCP, Port: ps.port, Bind: ps.bind, Error: ps.err})
	}
	return out
}

// checkPushPort prueft port/bind gegen die Ports der anderen Teile (ohne Verzeichnis: keine Pruefung).
func (m *Module) checkPushPort(ctx context.Context, bind string, port int) error {
	ps := m.pushState()
	ps.mu.Lock()
	reg := ps.reg
	ps.mu.Unlock()
	if reg == nil {
		return nil
	}
	return reg.Check(ctx, Name, []ports.Claim{{Owner: Name, Purpose: "Monitor64 Push", Proto: ports.TCP, Port: port, Bind: bind}})
}

// pushPort ist der eingestellte Port des Lauschers.
func (m *Module) pushPort(ctx context.Context) int {
	n, err := strconv.Atoi(m.st.SettingOr(ctx, setPushPort, ""))
	if err != nil || n < 1 || n > 65535 {
		return m64proto.DefaultPushPort
	}
	return n
}

// usesPush: mindestens ein eingeschalteter Agent-Zugang im Push-Betrieb (eine Abfrage ueber alle Zugaenge).
func (m *Module) usesPush(ctx context.Context) (bool, error) {
	accs, err := m.store.Accesses(ctx, "")
	if err != nil {
		return false, err
	}
	for _, a := range accs {
		if a.Type != "agent" || !a.Enabled {
			continue
		}
		var c accessConfig
		if json.Unmarshal(a.Config, &c) == nil && c.Mode == "push" {
			return true, nil
		}
	}
	return false, nil
}

// syncPush oeffnet bzw. schliesst den Lauscher passend zu den Zugaengen und zum eingestellten Port. Der Lauscher
// selbst bleibt dasselbe Objekt (die Clients halten den Zeiger), nur die Ports wechseln: ein neuer Port wird erst
// geoeffnet, dann der alte geschlossen (scheitert das Oeffnen, bleibt der alte offen und der Fehler kommt zurueck).
// Kann die Datenbank nicht gelesen werden, bleibt der Zustand.
func (m *Module) syncPush(ctx context.Context) error {
	m.mu.Lock()
	pl := m.push
	m.mu.Unlock()
	if pl == nil {
		return nil
	}
	m.pushMu.Lock()
	defer m.pushMu.Unlock()
	want, err := m.usesPush(ctx)
	if err != nil {
		m.log.Warn("monitor64: push listener: accesses not readable, keeping state", "err", err)
		return err
	}
	bind, port := m.st.SettingOr(ctx, setPushBind, ""), m.pushPort(ctx)
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	ps := m.pushState()
	ps.mu.Lock()
	ps.want, ps.port, ps.bind = want, port, bind
	ps.mu.Unlock()
	setErr := func(e error) {
		ps.mu.Lock()
		ps.err = ""
		if e != nil {
			ps.err = e.Error()
		}
		ps.mu.Unlock()
	}
	if !want {
		pl.StopListening()
		m.pushAddr = ""
		setErr(nil)
		return nil
	}
	if len(pl.Listening()) > 0 && m.pushAddr == addr {
		return nil
	}
	if err := m.checkPushPort(ctx, bind, port); err != nil {
		m.log.Warn("monitor64: push listener", "addr", addr, "err", err)
		setErr(err)
		return err
	}
	if _, err := pl.Rebind(addr); err != nil {
		m.log.Warn("monitor64: push listener", "addr", addr, "err", err)
		setErr(err)
		return err
	}
	m.pushAddr = addr
	setErr(nil)
	return nil
}

// pushPortErr macht aus einem Fehler beim Oeffnen des Push-Ports den Fehler fuer die API.
func pushPortErr(port int, err error) error {
	var ce *ports.ConflictError
	if errors.As(err, &ce) {
		return errBad("push_port_used", "port", port, "owner", ce.With.Owner+" ("+ce.With.Purpose+")")
	}
	return errBad("push_port_bind", "port", port, "error", err.Error())
}

// pushToken bestimmt den Token eines Agent-Zugangs: nur im Push-Betrieb; ein gueltiger Token aus der Eingabe (der
// Assistent holt ihn vorab fuer den Installationsbefehl) bzw. der bisherige bleibt, sonst ein neuer.
func pushToken(mode, in, old string, renew bool) string {
	switch {
	case mode != "push":
		return ""
	case renew:
		return transport.NewPushToken()
	case m64proto.ValidPushToken(in):
		return in
	case m64proto.ValidPushToken(old):
		return old
	}
	return transport.NewPushToken()
}

// apiPushToken: GET ein neuer Token fuer den Installationsbefehl im Assistenten (gibt keinen Zugriff).
func (m *Module) apiPushToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"token": transport.NewPushToken(), "port": m.pushPort(r.Context())})
}
