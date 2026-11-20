package healthchecks

import "encoding/json"

// Rolle „Nur lesen“ (Benutzerverwaltung im Kern): Passwort, Kopfzeilen (z. B. Authorization) und frei befuellbarer
// Request-Body der HTTP-Checks sowie die gesendeten Daten der TCP-Checks gehen nur an Administratoren - alle koennen
// Zugangsdaten enthalten.

var secretParams = []string{"basic_password", "headers", "body", "send"}

// redactParams: Parameter ohne die geheimen Felder (unveraendert, wenn keine da sind).
func redactParams(p json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if len(p) == 0 || json.Unmarshal(p, &m) != nil {
		return p
	}
	changed := false
	for _, k := range secretParams {
		if _, ok := m[k]; ok {
			delete(m, k)
			changed = true
		}
	}
	if !changed {
		return p
	}
	b, err := json.Marshal(m)
	if err != nil {
		return p
	}
	return b
}

// redactCheckRaw: Check-Objekt von ipv64 (Online-Checks) ohne geheime Parameter.
func redactCheckRaw(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return raw
	}
	p, ok := m["params"]
	if !ok {
		return raw
	}
	m["params"] = redactParams(p)
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return b
}
