package checks

// TokenHint kuerzt einen Check-Token fuer Logs und Audit: der Token ist zugleich die Berechtigung fuer die
// Push-Adresse und gehoert nicht im Klartext in Protokolle. Die ersten Zeichen reichen zum Zuordnen; kurze
// Kennungen (z. B. Nummern von Wartungsfenstern) bleiben unveraendert.
func TokenHint(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:6] + "…"
}
