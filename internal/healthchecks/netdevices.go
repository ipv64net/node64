package healthchecks

import (
	"context"
	"sort"
	"strings"
)

// Geraete aus DNS64 beim Anlegen eines Checks (GitHub #20): Auswahl uebernimmt IP und Name, Ping als Vorschlag.

// NetDevice ist ein Geraet aus DNS64 (Name vom Router bzw. aus der Gruppe, IP).
type NetDevice struct {
	Name string `json:"name,omitempty"`
	IP   string `json:"ip"`
}

// SetNetDevices liefert die Geraete aus DNS64 (fn liefert nil, solange DNS64 nicht laeuft).
func (m *Module) SetNetDevices(fn func(context.Context) []NetDevice) {
	m.netDevices = func(ctx context.Context) []NetDevice {
		list := fn(ctx)
		sort.SliceStable(list, func(i, j int) bool { // mit Namen zuerst, dann nach Name bzw. IP
			a, b := list[i], list[j]
			if (a.Name == "") != (b.Name == "") {
				return a.Name != ""
			}
			if a.Name != b.Name {
				return strings.ToLower(a.Name) < strings.ToLower(b.Name)
			}
			return a.IP < b.IP
		})
		return list
	}
}
