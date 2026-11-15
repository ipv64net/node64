package ipam64

import (
	"context"

	"github.com/ipv64net/node64/internal/module"
)

// Card liefert die Dashboard-Karte (module.CardProvider): Praefixe, belegte Adressen, Konflikte. Der Anteil der
// Belegung zaehlt nur IPv4-Praefixe mit Groesse (IPv6 und Container haben keine sinnvolle Groesse).
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	used, conflicts := 0, 0
	var size, usedV4 int64
	for _, n := range snap.Nets {
		used, conflicts = used+n.Used, conflicts+n.Conflicts
		if n.IsV4() && !n.Container() && n.Size > 0 {
			size += n.Size
			usedV4 += int64(n.Used)
		}
	}
	c := &module.Card{TitleKey: "nav.ipam64", Icon: "bi-grid-3x3-gap", Image: "ipam64.svg", Path: "/ipam64", Stats: []module.CardStat{
		{LabelKey: "ipam64.card.prefixes", Value: int64(len(snap.Nets))},
		{LabelKey: "ipam64.card.used", Value: int64(used)},
		{LabelKey: "ipam64.card.conflicts", Value: int64(conflicts)},
	}}
	if size > 0 {
		c.Stats[1].Pct = min(100, float64(usedV4)*100/float64(size))
	}
	if conflicts > 0 {
		c.Stats[2].Class = "text-danger"
	}
	return c, nil
}
