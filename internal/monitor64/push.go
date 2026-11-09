package monitor64

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"

	"github.com/ipv64net/node64/internal/monitor64/transport"
)

// Push-Betrieb des Agents (Plan Phase 3): Hosts hinter NAT bzw. VPS bauen die Verbindung selbst zur Node auf
// (transport.PushListener). Nur die TCP-Richtung dreht sich: der Agent bleibt SSH-Server und prueft die Node ueber
// keys, die Node pinnt seinen Hostschluessel. Der Token im Installationsbefehl ist nur der Wegweiser zum Zugang.

const (
	setPushPort = "monitor64.push_port" // TCP-Port des Lauschers (Standard transport.DefaultPushPort)
	setPushBind = "monitor64.push_bind" // Adresse des Lauschers (leer = alle)
)

// pushPort ist der eingestellte Port des Lauschers.
func (m *Module) pushPort(ctx context.Context) int {
	n, err := strconv.Atoi(m.st.SettingOr(ctx, setPushPort, ""))
	if err != nil || n < 1 || n > 65535 {
		return transport.DefaultPushPort
	}
	return n
}

// usesPush: mindestens ein eingeschalteter Agent-Zugang im Push-Betrieb.
func (m *Module) usesPush(ctx context.Context) bool {
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return false
	}
	for _, h := range hosts {
		accs, err := m.store.Accesses(ctx, h.UID)
		if err != nil {
			continue
		}
		for _, a := range accs {
			if a.Type != "agent" || !a.Enabled {
				continue
			}
			var c accessConfig
			if json.Unmarshal(a.Config, &c) == nil && c.Mode == "push" {
				return true
			}
		}
	}
	return false
}

// syncPush oeffnet bzw. schliesst den Lauscher passend zu den Zugaengen und zum eingestellten Port. Der Lauscher
// selbst bleibt dasselbe Objekt (die Clients halten den Zeiger), nur Listen/StopListening wechseln.
func (m *Module) syncPush(ctx context.Context) {
	m.mu.Lock()
	pl := m.push
	m.mu.Unlock()
	if pl == nil {
		return
	}
	m.pushMu.Lock()
	defer m.pushMu.Unlock()
	want := m.usesPush(ctx)
	addr := net.JoinHostPort(m.st.SettingOr(ctx, setPushBind, ""), strconv.Itoa(m.pushPort(ctx)))
	cur := pl.Listening()
	if !want || (len(cur) > 0 && m.pushAddr != addr) {
		pl.StopListening()
		m.pushAddr = ""
	}
	if want && len(pl.Listening()) == 0 {
		if _, err := pl.Listen(addr); err != nil {
			m.log.Warn("monitor64: push listener", "addr", addr, "err", err)
			return
		}
		m.pushAddr = addr
	}
}

// pushToken bestimmt den Token eines Agent-Zugangs: nur im Push-Betrieb; ein gueltiger Token aus der Eingabe (der
// Assistent holt ihn vorab fuer den Installationsbefehl) bzw. der bisherige bleibt, sonst ein neuer.
func pushToken(mode, in, old string, renew bool) string {
	switch {
	case mode != "push":
		return ""
	case renew:
		return transport.NewPushToken()
	case transport.ValidPushToken(in):
		return in
	case transport.ValidPushToken(old):
		return old
	}
	return transport.NewPushToken()
}

// apiPushToken: GET ein neuer Token fuer den Installationsbefehl im Assistenten (gibt keinen Zugriff).
func (m *Module) apiPushToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"token": transport.NewPushToken(), "port": m.pushPort(r.Context())})
}
