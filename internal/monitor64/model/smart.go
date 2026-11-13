package model

import "time"

// SmartDetail sind alle zuletzt gelesenen SMART-Werte einer Platte zum Nachschlagen (Dialog in der Dienste-Tabelle).
// Sie gehoeren nicht zum gespeicherten Stand eines Dienstes: der Kern haelt je Platte nur den letzten Satz im
// Speicher (kein Verlauf, nichts in der Datenbank).
type SmartDetail struct {
	Type     string    `json:"type,omitempty"` // ata, nvme, scsi ...
	Model    string    `json:"model,omitempty"`
	Serial   string    `json:"serial,omitempty"`
	Firmware string    `json:"firmware,omitempty"`
	Size     uint64    `json:"size,omitempty"`   // Bytes
	Passed   *bool     `json:"passed,omitempty"` // Gesamtzustand (nil = unbekannt)
	At       time.Time `json:"at,omitzero"`      // wann gelesen (leer: der Kern setzt die Zeit der Abfrage)
	// Partial: die Quelle liefert nur die ausgewerteten Werte, nicht alle Attribute (Windows, aeltere Agents)
	Partial bool         `json:"partial,omitempty"`
	Attrs   []SmartAttr  `json:"attrs,omitempty"`  // ATA-Attribute
	Values  []SmartValue `json:"values,omitempty"` // NVMe, SCSI bzw. einzelne Werte
}

// SmartAttr ist ein ATA-Attribut. Value, Worst und Thresh sind die normierten Werte (nil = nicht geliefert).
type SmartAttr struct {
	ID     int    `json:"id"`
	Name   string `json:"name,omitempty"`
	Value  *int   `json:"value,omitempty"`
	Worst  *int   `json:"worst,omitempty"`
	Thresh *int   `json:"thresh,omitempty"`
	Raw    string `json:"raw,omitempty"`
	Failed string `json:"failed,omitempty"` // "now" (unter der Schwelle), "past" (war es schon einmal)
}

// SmartValue ist ein benannter Wert. Key nennt einen bekannten Wert, den die Oberflaeche uebersetzt
// (available_spare, power_on_hours ...); sonst steht in Name der Name vom Geraet. Zahl mit Einheit (%, °C, B, h,
// min, hex) oder Text.
type SmartValue struct {
	Key   string  `json:"key,omitempty"`
	Name  string  `json:"name,omitempty"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit,omitempty"`
	Text  string  `json:"text,omitempty"`
}
