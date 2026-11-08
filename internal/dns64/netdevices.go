package dns64

import (
	"context"
	"net/netip"
)

// Geraete aus DNS64 fuer andere Module (GitHub #20): Healthchecks bietet sie beim Anlegen eines Checks zur Auswahl an,
// die Seite Gruppen verlinkt je Geraet auf "neuer Check" (nur wenn Healthchecks laeuft).

// NetDevice ist ein Geraet der letzten 24 Stunden.
type NetDevice struct {
	Name string // Name vom Router bzw. aus der Gruppe ("" = unbekannt)
	IP   string
}

// SetHealthchecks: f meldet, ob Healthchecks laeuft (Knopf "Als Check" bei den Geraeten).
func (m *Module) SetHealthchecks(f func() bool) { m.hcOn = f }

// NetDevices liefert die Geraete der letzten 24 Stunden mit voller Adresse (nil = DNS-Dienst laeuft nicht). Gekuerzte
// Adressen (Anonymisierung) taugen nicht als Ziel und fehlen.
func (m *Module) NetDevices(ctx context.Context) []NetDevice {
	e := m.running()
	if e == nil {
		return nil
	}
	list, err := m.devices(ctx, e)
	if err != nil {
		return nil
	}
	out := make([]NetDevice, 0, len(list))
	for _, d := range list {
		if a, err := netip.ParseAddr(d.IP); err != nil || a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		out = append(out, NetDevice{Name: d.Name, IP: d.IP})
	}
	return out
}
