# SNMP-Profile für Monitor64

Ein Profil beschreibt, welche herstellerspezifischen OIDs ein Gerät liefert und was Monitor64 daraus macht
(Messgröße mit Einheit und Standard-Schwelle, Zustand oder Anzeigetext). Die Standard-MIBs (IF-MIB, HOST-RESOURCES,
UCD-SNMP, IEEE8023-LAG, ENTITY-SENSOR, Printer-MIB, UPS-MIB) fragt der Sammler immer selbst ab – Profile ergänzen nur.

Die Node wählt Profile selbst über `sysObjectID`/`sysDescr` und optional eine Probe-OID. Mehrere passende Profile
gelten zusammen. Jede Datei `*.json` in diesem Ordner wird beim Bauen eingebettet und beim Start geprüft; der Test
`TestProfilesLoad` lädt alle Profile – ein fehlerhaftes Profil lässt den Test scheitern.

Beiträge sind willkommen (Pull-Request mit Profil und, wenn möglich, einem `snmpwalk -On` des Geräts unter
`../testdata/` samt Test). Bitte nur lesende OIDs, keine Zugangsdaten oder Seriennummern in Testdaten.

## Aufbau

```json
{
  "id": "synology",
  "name": "Synology DSM",
  "device": "nas",
  "verified": false,
  "source": "SYNOLOGY-SYSTEM-MIB, SYNOLOGY-DISK-MIB",
  "match": { "object_ids": [".1.3.6.1.4.1.8072.3.2.10"], "descr": ["synology"], "probe": ".1.3.6.1.4.1.6574.1.1.0" },
  "scalars": [ ... ],
  "tables": [ ... ]
}
```

| Feld | Bedeutung |
|---|---|
| `id` | eindeutig, `a-z0-9_-`, höchstens 32 Zeichen |
| `name` | Anzeigename (höchstens 64 Zeichen) |
| `device` | Geräteart: `nas`, `ups`, `printer`, `switch`, `router`, `ap`, `server`, `pdu`, `device` oder leer |
| `verified` | `true`, wenn an einem echten Gerät geprüft (sonst nur nach MIB-Datei) |
| `source` | woher die OIDs stammen (MIB, Firmware-Version, Gerät) |
| `match` | Auswahl, siehe unten |
| `scalars` | Einzelwerte (GET) |
| `tables` | Tabellen (GETBULK), je Zeile ein Dienst |

Unbekannte Felder sind ein Fehler.

### Auswahl (`match`)

Das Profil gilt, wenn (`sysObjectID` gleich einem Eintrag aus `object_ids` ist oder darunter liegt **oder**
`sysDescr` einen Eintrag aus `descr` enthält – ohne Groß-/Kleinschreibung) **und** (keine `probe` angegeben ist
**oder** die `probe`-OID einen Wert liefert). Ohne `object_ids` und `descr` entscheidet nur die Probe. Viele Geräte
melden die allgemeine net-snmp-Kennung `.1.3.6.1.4.1.8072.3.2.10` – dann immer eine Probe-OID des Herstellers angeben.

### Dienst (`key`, `service`, `kind`, `default`)

Jeder Skalar bzw. jede Tabelle nennt den Dienst, in den der Wert geht:

| Feld | Bedeutung |
|---|---|
| `key` | fester Dienst-Schlüssel, z. B. `ups`, `temp:system`, `disk:{name}` (Tabellen brauchen `{name}` oder `{index}`) |
| `service` | Anzeigename, Platzhalter wie bei `key` |
| `kind` | Dienst-Art (`temp`, `disk`, `raid`, `zfs`, `store`, `ups`, `poe`, `fan`, `wlan`, `hw` …) |
| `default` | beim Erkennen vorgeschlagen (Standard `true`) |

Mehrere Werte mit demselben `key` landen im selben Dienst. Bitte die Schlüssel und Arten des Sammlers verwenden, damit
die Standard-Schwellen gleich wirken: `temp:<name>` (Temperatur), `disk:<name>` (Platte), `raid:<name>`, `zfs:<name>`,
`store:<name>` (Volume/Pool), `ups` (USV), `if:<ifName>` (Port). Liefert der Sammler denselben Schlüssel schon aus einer
Standard-MIB (z. B. `ups` aus der UPS-MIB), ergänzt das Profil nur fehlende Messgrößen und Zustände.

Platzhalter: `{name}` = Wert der Spalte `name_col` (bereinigt), `{index}` = Index der Zeile.

### Skalare

```json
{ "key": "ups", "service": "USV", "kind": "ups", "oid": ".1.3.6.1.4.1.318.1.1.1.2.2.3.0",
  "metric": "runtime", "unit": "s", "factor": 0.01, "rule": "ups.runtime", "min": 0 }
```

### Tabellen

```json
{ "key": "disk:{name}", "service": "Platte {name}", "kind": "disk", "oid": ".1.3.6.1.4.1.6574.2.1.1", "name_col": 2,
  "filter": { "col": 4, "values": [1] },
  "columns": [
    { "col": 6, "metric": "temp", "unit": "°C", "rule": "disk.temp" },
    { "col": 5, "text": { "1": "Normal", "5": "Abgestürzt" }, "fact": { "code": "smart_failed", "when": [5] } }
  ] }
```

`oid` ist die Entry-OID (`…Table.1`); Spalte `n` ist `oid.n`. `filter` nimmt nur Zeilen, deren Spalte einen der Werte
hat (z. B. MikroTik-Sensoren nach Einheit).

### Werte

Jeder Skalar bzw. jede Spalte braucht mindestens eines von `metric`, `fact`, `text`, `label`.

| Feld | Bedeutung |
|---|---|
| `metric` | Name der Messgröße (`a-z0-9_`), z. B. `temp`, `used`, `charge`, `runtime` |
| `unit` | `%`, `°C`, `B`, `B/s`, `Mbit/s`, `s`, `V`, `A`, `W`, `VA`, `rpm`, `Hz`, `dBm` oder leer |
| `factor`, `offset` | Wert = Rohwert × `factor` + `offset` (Standard 1 und 0); z. B. Zehntelgrad `0.1`, TimeTicks → s `0.01`, Restlebensdauer → Verschleiß `-1`/`100` |
| `rule` | Art für die Standard-Schwellen: `cpu.util`, `load.core`, `mem.used`, `swap.used`, `fs.used`, `store.used`, `disk.temp`, `disk.temp_nvme`, `ssd.wear`, `if.util`, `if.errrate`, `printer.supply`, `ups.runtime`, `poe.used`, `temp.system` |
| `counter` | Zähler: Rate je Sekunde (vor `factor`), Überlauf/Neustart wird erkannt |
| `leading` | Zahl am Textanfang lesen (`"37 C/98 F"` → 37) |
| `min`, `max` | gültiger Bereich des Rohwerts, sonst wird der Wert verworfen (z. B. `-1` = nicht unterstützt) |
| `hide` | Messwert nicht im Dienst-Text zeigen |
| `text` | Rohwert → Anzeigetext (`{"1": "Normal"}`); ein leerer Text blendet den Wert aus |
| `label` | Rohtext mit diesem Vorsatz in den Dienst-Text (`"Modell"` → „Modell DS920+“) |
| `pct` | Belegung in % aus zwei Werten: `{"total": "5", "free": "4"}` bzw. `"used"` (Tabellen: Spaltennummern, Skalare: OIDs), optional `"unit"` = Bytes je Einheit; liefert zusätzlich `free` in Bytes |
| `fact` | Zustand, siehe unten |

### Zustände (`fact`)

```json
{ "code": "raid_degraded", "when": [11, 12], "text": "Speicherpool beeinträchtigt" }
```

Genau eine Bedingung: `when` (Wert in Liste), `ok` (Wert nicht in Liste), `when_text`/`ok_text` (Teiltext, ohne
Groß-/Kleinschreibung), `above`/`below` (Grenze). `text` ist der Meldungstext (Standard: Anzeigetext bzw. Rohwert).

Erlaubte Codes: `smart_failed`, `smart_sectors`, `raid_degraded`, `zfs_degraded`, `store_inactive`, `bond_member_down`,
`lacp_mismatch`, `updates_security`, `reboot_required`, `ups_on_battery`, `ups_low_battery`, `ups_replace_battery`,
`ups_alarm`, `printer_error`, `paper_empty`, `hw_failed`, `poe_fault`, `if_down`, `if_speed_low`, `if_half_duplex`,
`restarted`. Wie stark ein Zustand meldet, legen die Regeln in Monitor64 fest (nicht das Profil).

## English summary

Profiles are JSON files that map vendor OIDs (`scalars`, `tables`) to Monitor64 services: a metric with unit, factor
and default threshold kind (`rule`), a state (`fact`) or display text. A profile applies when `sysObjectID` starts
with one of `match.object_ids` or `sysDescr` contains one of `match.descr`, and the optional `match.probe` OID returns
a value. Unknown fields are rejected; `TestProfilesLoad` validates every file. Pull requests with a profile and a
`snmpwalk -On` capture (no credentials or serial numbers) are welcome.
