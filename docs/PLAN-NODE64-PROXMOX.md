# Plan: Proxmox-VE-Überwachung (Healthchecks)

Stand 2026-10-21, Wunsch und Entscheidungen Dennis. Nur **Überwachung** – Node64 startet, stoppt oder ändert in
Proxmox nichts (nur lesende API-Aufrufe).

## Entscheidungen

| Thema | Entscheidung |
|---|---|
| Ort | eigener Menüpunkt **„Proxmox VE“ unter Healthchecks** (wie Statusseiten), läuft nur, wenn Healthchecks an ist |
| Systeme | **mehrere** Proxmox-Systeme; ein System = Einzel-Node oder Cluster (mehrere Nodes), hierarchisch System → Node → VM/Container |
| Als Check | je VM/Container und je Node wählbar **„auch als Check führen“** → normaler Healthchecks-Check (Typ `proxmox`), damit Statusseiten, Sync mit ipv64, Uptime-Balken und die vorhandenen Benachrichtigungen greifen |
| Messdaten | **nur lokal** (Verlauf in der Node-Datenbank, Graphen, Prometheus); an ipv64 geht nur der Zustand über die Checks |
| Umfang v1 | Zustand und Leistung von Nodes, VMs (QEMU) und Containern (LXC), Erreichbarkeit der API, Schwellen mit Dauer, Benachrichtigung je System/Node/VM einstellbar. **Noch nicht:** Backups, Storage/Disks/ZFS/Ceph, HA/Replikation, Updates/Zertifikate (später) |
| Abfrage | `cluster/resources` alle **30 s** (einstellbar 15–300 s, ein Aufruf je System für alles), `cluster/status` alle 60 s, Pausen-Zustand laufender VMs alle 2 min |

## Proxmox-API (nur lesend)

- **Zugang:** API-Token (`Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>`), empfohlen Rolle
  **PVEAuditor** auf `/` (nur lesen), Token ohne „Privilege Separation“-Falle erklären. Token verschlüsselt
  gespeichert (secrets.Box).
- **TLS:** Zertifikat per System-CA oder **festgepinnter SHA-256-Fingerabdruck** (beim Anlegen angezeigt und
  bestätigt, wie bei Proxmox selbst üblich, weil meist selbstsigniert). Kein „Prüfung aus“.
- **Endpunkte:** `GET /api2/json/version`; `GET /cluster/status` (Clustername, `quorate`, Nodes mit `online`, `ip`);
  `GET /cluster/resources?type=vm` und `?type=node` (je Gast: `vmid`, `name`, `node`, `type` qemu/lxc, `status`,
  `template`, `lock`, `tags`, `hastate`, `cpu`, `maxcpu`, `mem`, `maxmem`, `disk`, `maxdisk`, `netin`, `netout`,
  `diskread`, `diskwrite`, `uptime`; je Node: `status`, `cpu`, `maxcpu`, `mem`, `maxmem`, `disk`, `maxdisk`,
  `uptime`); `GET /nodes/{node}/qemu/{vmid}/status/current` nur für laufende VMs (`qmpstatus`: running, paused,
  suspended, prelaunch).
- **Cluster:** ein System hat eine Liste von Adressen (eine reicht, weitere Nodes werden aus `cluster/status`
  übernommen); fällt eine Adresse aus, wird die nächste genommen. Node offline erkennt man an `cluster/status`.

## Zustände (Anzeige und Bewertung)

| Gast | Zustand | Bewertung |
|---|---|---|
| läuft | `running` (qmpstatus running) | ok |
| angehalten | `qmpstatus` paused | Störung (wählbar) |
| suspendiert | `lock` suspended bzw. qmpstatus suspended | Störung (wählbar) |
| Backup läuft | `lock` backup | ok, Hinweis „Backup“ |
| Migration, Snapshot, Klonen … | `lock` migrate/snapshot/… | ok, Hinweis |
| abgestürzt / hängt | `qmpstatus` internal-error, guest-panicked, io-error | Störung (immer, Kernfall „Maschine abgestürzt“) |
| gestoppt | `stopped` | Störung, wenn erwartet „läuft“ (Standard: war beim Einrichten an); unerwartet von „läuft“ auf „gestoppt“ = Absturz bzw. Ausfall |
| Node offline | Node `offline`/`unknown` | Störung des Nodes, seine Gäste „unbekannt“ |
| System nicht erreichbar | API antwortet nicht | Störung des Systems |
| Neustart | `uptime` springt zurück bei weiterlaufendem Gast | Hinweis „neu gestartet“ |

Vorlagen (`template=1`) werden nie überwacht. Tag `nomonitor` (Proxmox-Tag) schließt einen Gast aus.

## Benachrichtigung

Regeln mit Vererbung **System → Node → Gast** (unten überschreibt oben): Zustand (aus/an je Ereignis: gestoppt,
angehalten, suspendiert, Node offline, System nicht erreichbar, Neustart), Schwellen CPU %, RAM %, Disk % (nur LXC
sinnvoll) jeweils mit Dauer in Minuten, Verzögerung (erst nach N Abfragen), Entwarnung. Versand über das vorhandene
Benachrichtigungssystem (Kanäle, Ruhezeiten) mit neuen Arten `proxmox_down`, `proxmox_up`, `proxmox_threshold`,
`proxmox_threshold_ok`. Ist ein Gast „als Check“ geführt, kommen Zustandsmeldungen über den Check (keine doppelten),
Schwellen weiter über Proxmox.

## Speicher (lokal)

Systeme, Node-/Gast-Einstellungen und Regeln in der Node-Datenbank (Scope healthchecks). Verlauf (Dennis 2026-10-21:
so lange wie in den lokalen Einstellungen der Healthchecks): 1-Minuten-Werte 48 h, 5-Minuten-Werte so lange wie
`hc.raw_days` (Einzelmessungen), Stundenwerte so lange wie `hc.hourly_days` (0 = unbegrenzt) – CPU, RAM, Disk, Netz
rein/raus, Disk lesen/schreiben als Raten.

## Oberfläche

`/healthchecks/proxmox`: Systeme mit Zustand (Cluster: Quorum, Nodes), darunter Nodes und Gäste als Tabelle (Name,
ID, Typ, Zustand, CPU, RAM, Disk, Netz, Uptime, Sparklines), Filter, Klick → Detail mit Graphen (1 h/24 h/7 d/30 d),
Regeln, „als Check führen“. Assistent zum Anlegen (Adresse, Token, Fingerabdruck bestätigen, Test). Startseiten-Karte:
Systeme, Gäste laufend/gestört, letzte Störung.

## Umsetzung (Schnittstellen, verbindlich für die parallelen Teile)

Vertrag: `internal/proxmox/types.go`.

| Teil | Dateien | Inhalt |
|---|---|---|
| Client + Abfrage | `internal/proxmox/client.go`, `poller.go` (+ Tests mit nachgebautem Proxmox) | Token, TLS-Pinning, Failover über Adressen, Abfragen und Takt, Snapshot je System, Raten aus Zählern, Neustart-Erkennung |
| Speicher + Regeln | `internal/proxmox/store.go`, `history.go`, `rules.go`, Migration in `internal/healthchecks/migrations/0015_proxmox.sql` | Systeme/Einstellungen/Regeln, Verlauf mit Verdichtung und Aufräumen, Auswertung der Regeln → Ereignisse |
| Einbindung + Oberfläche | `internal/healthchecks/proxmox_*.go`, Templates, Check-Typ `proxmox` in `internal/checks`, `internal/notify` (neue Arten), Menü, API, Prometheus, Doku | Start/Stopp mit Healthchecks, Seiten, Assistent, „als Check“, Benachrichtigung, Startseiten-Karte |
