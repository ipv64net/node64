package m64proto

// ApplyATAAttr wertet ein ATA-Attribut fuer die Zaehler des SMART-Abschnitts aus - eine Stelle fuer Agent, SSH und
// smartctl_exporter (Review 15): 5 Reallocated, 197 Pending, 198 Uncorrectable, 199 CRC-Fehler (Rohwert); der
// normierte Wert von 177 (Samsung), 231 (SSD_Life_Left), 233 (Intel), 202 (Crucial) und 169 (WD) ist die
// verbleibende Lebensdauer in % - der erste Treffer gilt als Verschleiss.
func (s *SMART) ApplyATAAttr(id, value int, raw uint64) {
	u := func(v uint64) *uint64 { return &v }
	switch id {
	case 5:
		s.Reallocated = u(raw)
	case 197:
		s.Pending = u(raw)
	case 198:
		s.Uncorrectable = u(raw)
	case 199:
		s.CRCErrors = u(raw)
	case 177, 231, 233, 202, 169:
		if s.WearPercentUsed == nil && value > 0 && value <= 100 {
			w := float64(100 - value)
			s.WearPercentUsed = &w
		}
	}
}
