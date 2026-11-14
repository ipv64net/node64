package ipam64

import (
	"context"
	"encoding/json"
)

// exportData ist der Inhalt im Export der Node (module.Exporter): Praefixe, Adressbereiche, feste Adressen. Die
// Sichtungen gehoeren nicht dazu (je Node, kurzlebig).
type exportData struct {
	Prefixes  []Prefix  `json:"prefixes"`
	Ranges    []Range   `json:"ranges"`
	Addresses []Address `json:"addresses"`
}

// Export liefert die Daten des Moduls.
func (m *Module) Export(ctx context.Context) (any, error) {
	var d exportData
	var err error
	if d.Prefixes, err = m.Prefixes(ctx); err != nil {
		return nil, err
	}
	if d.Ranges, err = m.Ranges(ctx); err != nil {
		return nil, err
	}
	if d.Addresses, err = m.Addresses(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// Import uebernimmt Daten aus einem Export (gleiche uid = ersetzen, gleicher Wert unter anderer uid = auslassen) und
// liefert die Zahl der uebernommenen Eintraege. Praefixe zuerst, damit Bereiche und Adressen ihr Praefix finden.
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	var d exportData
	if err := json.Unmarshal(raw, &d); err != nil {
		return 0, err
	}
	n := 0
	for _, p := range d.Prefixes {
		if !uidRe.MatchString(p.UID) {
			p.UID = ""
		} else if old, err := m.prefixByUID(ctx, p.UID); err != nil {
			return n, err
		} else if old == nil {
			if err := normalizePrefix(&p); err != nil {
				continue
			}
			if err := m.writePrefix(ctx, p); err == nil {
				m.changed(ctx, ClusterItemPrefixes, p.UID, false)
				n++
			}
			continue
		}
		if _, err := m.SavePrefix(ctx, p, p.UpdatedBy); err == nil {
			n++
		}
	}
	for _, r := range d.Ranges {
		if !uidRe.MatchString(r.UID) {
			r.UID = ""
		} else if old, err := m.rangeByUID(ctx, r.UID); err != nil {
			return n, err
		} else if old == nil {
			if err := normalizeRange(&r); err != nil {
				continue
			}
			if err := m.writeRange(ctx, r); err == nil {
				m.changed(ctx, ClusterItemRanges, r.UID, false)
				n++
			}
			continue
		}
		if _, err := m.SaveRange(ctx, r, r.UpdatedBy); err == nil {
			n++
		}
	}
	for _, a := range d.Addresses {
		if !uidRe.MatchString(a.UID) {
			a.UID = ""
		} else if old, err := m.addressWhere(ctx, `uid = ?`, a.UID); err != nil {
			return n, err
		} else if old == nil {
			if err := normalizeAddress(&a); err != nil {
				continue
			}
			if dup, _ := m.addressWhere(ctx, `address = ?`, a.Address); dup != nil {
				continue
			}
			if err := m.writeAddress(ctx, a); err == nil {
				m.changed(ctx, ClusterItemAddresses, a.UID, false)
				n++
			}
			continue
		}
		if _, err := m.SaveAddress(ctx, a, a.UpdatedBy); err == nil {
			n++
		}
	}
	return n, nil
}
