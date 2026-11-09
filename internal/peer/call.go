package peer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
)

// Anfragen eines Moduls an eine andere Node (POST /peer/v2/call/{modul}/{name}): fuer Daten, die nicht abgeglichen,
// sondern live bei der Node abgefragt werden (z. B. Verlauf von Monitor64) oder einen Anstoss (Trap). Signiert und an
// die TLS-Verbindung gebunden wie alle Anfragen des Clusters. Beantwortet wird nur, wenn das Modul hier angemeldet ist
// und mindestens einer seiner Bereiche hier und bei der anfragenden Node eingeschaltet ist.

// CallHandler beantwortet eine Anfrage einer anderen Node (from: Kennung der Absenderin, body: JSON der Anfrage).
// Die Antwort wird als JSON geschickt; ein Fehler geht als 400 mit seinem Text zurueck.
type CallHandler func(ctx context.Context, from string, body []byte) (any, error)

var callNameRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// ErrCallUnavailable: die andere Node beantwortet die Anfrage nicht (Modul oder Bereich dort aus, aeltere Version).
var ErrCallUnavailable = errors.New("cluster call not available on that node")

// RegisterCall meldet eine Anfrage eines Moduls an (beim Start, vor Run; module = ID des Providers).
func (m *Manager) RegisterCall(module, name string, h CallHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.calls == nil {
		m.calls = map[string]CallHandler{}
	}
	m.calls[module+"/"+name] = h
}

// registerCall haengt den Endpunkt an (aus Register).
func (m *Manager) registerCall(mux *http.ServeMux) {
	mux.Handle("POST /peer/v2/call/{module}/{name}", m.Handle(m.handleCall))
}

func (m *Manager) callHandler(module, name string) CallHandler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[module+"/"+name]
}

func (m *Manager) handleCall(w http.ResponseWriter, r *http.Request, from *Member, body []byte) {
	module, name := r.PathValue("module"), r.PathValue("name")
	h := m.callHandler(module, name)
	if h == nil || m.provider(module) == nil || len(m.wants(m.syncCaps(r.Context()), *from, module)) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": ErrCallUnavailable.Error()})
		return
	}
	out, err := h(r.Context(), from.NodeID, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// Call schickt eine Anfrage an das Modul einer anderen Node (in als JSON, Antwort nach out). Ausgesetzte und
// unbekannte Mitglieder bekommen nichts; ohne Frist in ctx gilt das Zeitlimit des Clusters (10 s).
func (m *Manager) Call(ctx context.Context, nodeID, module, name string, in, out any) error {
	if !callNameRe.MatchString(name) || !callNameRe.MatchString(module) {
		return errors.New("invalid cluster call")
	}
	x, err := m.member(ctx, nodeID)
	if err != nil {
		return err
	}
	if x == nil {
		return ErrUnknownMember
	}
	if in == nil {
		in = struct{}{}
	}
	var raw json.RawMessage
	if err := m.call(ctx, *x, http.MethodPost, "/peer/v2/call/"+module+"/"+name, in, &raw); err != nil {
		// 404 mit diesem Text (Modul bzw. Bereich dort aus) oder ohne (aeltere Version ohne den Endpunkt)
		var se *statusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound && (se.Msg == ErrCallUnavailable.Error() || se.Msg == "") {
			return ErrCallUnavailable
		}
		return err
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
