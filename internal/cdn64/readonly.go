package cdn64

// Rolle „Nur lesen“ (Benutzerverwaltung im Kern): Werte eigener Request-Header eines Hosts und seiner Locations
// koennen Zugangsdaten enthalten (Authorization, Token) und gehen nur an Administratoren; die Namen bleiben sichtbar.
// Andere Geheimnisse gibt PROXY64 nie aus: Passwort-Hashes und Keys der Zugriffslisten (AccessList.public),
// Tunnel-Token (onlineConf) und Listen-Token der Blocklisten.

// redactedValue ersetzt den Wert eines ausgeblendeten Headers.
const redactedValue = "***"

// redactHeaders: Kopie der Liste mit ausgeblendeten Werten.
func redactHeaders(hs []Header) []Header {
	if len(hs) == 0 {
		return hs
	}
	out := make([]Header, len(hs))
	for i, x := range hs {
		out[i] = Header{Name: x.Name, Value: redactedValue}
	}
	return out
}

// redactSecrets: Kopie des Hosts ohne Werte der Request-Header (Host und Locations); h bleibt unveraendert.
func (h *Host) redactSecrets() *Host {
	cp := *h
	cp.Advanced.RequestHeaders = redactHeaders(h.Advanced.RequestHeaders)
	if h.Locations != nil {
		cp.Locations = make([]Location, len(h.Locations))
		for i, l := range h.Locations {
			if l.Advanced != nil {
				la := *l.Advanced
				la.RequestHeaders = redactHeaders(la.RequestHeaders)
				l.Advanced = &la
			}
			cp.Locations[i] = l
		}
	}
	return &cp
}
